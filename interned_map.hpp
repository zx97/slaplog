#pragma once
//
// interned_map.hpp — compact string-keyed maps for the aggregate.
//
// The filter dimensions of a busy directory carry hundreds of thousands of
// entries, and `std::map<std::string, V>` costs ~150–250 bytes each: a red-black
// node (32 B), an owning std::string (32 B, plus a heap buffer once the key
// exceeds the small-string capacity), the value, and allocator headers.  These
// maps keep the characters **once** in an arena, refer to them by 32-bit id and
// store the entries in an open-addressing table, so an entry costs its id, its
// value, and its share of the shared characters.
//
// Iteration order is unspecified (hash order).  Callers that print or serialise
// sort first — the report helpers sort by (value, key), and `sorted_by_key()`
// exists for the writer and for the one report that groups by application — so
// both the output and the files stay deterministic.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

// ------------------------------------------------------------------- pool --
// Append-only arena: every string is stored once as [u32 length][bytes], and an
// id is its offset + 1 (0 means "not interned").  A small open-addressing index
// deduplicates on insert.
class StringPool {
public:
    uint32_t intern(std::string_view s) {
        if (s.empty()) return 0;          // the empty string needs no storage
        // A view may point into this very arena (when a map is merged into
        // another map sharing the same pool): growing the arena while copying
        // from it would read freed bytes.  Copy first in that case.
        const auto* base = reinterpret_cast<const char*>(arena_.data());
        if (s.data() >= base && s.data() < base + arena_.size())
            return intern(std::string(s));
        if (index_.empty()) rehash(64);
        size_t slot = hash(s) & mask_;
        while (index_[slot]) {
            const uint32_t id = index_[slot];
            if (view(id) == s) return id;
            slot = (slot + 1) & mask_;
        }
        const uint32_t off = static_cast<uint32_t>(arena_.size());
        const uint32_t len = static_cast<uint32_t>(s.size());
        arena_.resize(off + sizeof len);
        std::memcpy(&arena_[off], &len, sizeof len);
        arena_.append(s.data(), s.size());
        const uint32_t id = off + 1;
        index_[slot] = id;
        ++count_;
        if (count_ * 10 >= index_.size() * 7) rehash(index_.size() * 2);
        return id;
    }

    std::string_view view(uint32_t id) const {
        if (!id) return {};
        const size_t off = id - 1u;
        uint32_t len = 0;
        std::memcpy(&len, arena_.data() + off, sizeof len);
        return std::string_view(arena_.data() + off + sizeof len, len);
    }

    size_t size() const { return count_; }

    void clear() {
        arena_.clear();
        index_.clear();
        count_ = 0;
        mask_ = 0;
    }

    static uint64_t hash(std::string_view s) {
        uint64_t h = 1469598103934665603ULL;          // FNV-1a
        for (unsigned char c : s) {
            h ^= c;
            h *= 1099511628211ULL;
        }
        return h;
    }

private:
    void rehash(size_t n) {
        std::vector<uint32_t> old(n, 0);
        old.swap(index_);
        mask_ = n - 1;
        for (uint32_t id : old) {
            if (!id) continue;
            size_t slot = hash(view(id)) & mask_;
            while (index_[slot]) slot = (slot + 1) & mask_;
            index_[slot] = id;
        }
    }

    std::string arena_;             // [u32 length][bytes] ...
    std::vector<uint32_t> index_;   // id, 0 = empty
    size_t count_ = 0;
    size_t mask_ = 0;
};

// A pool may be shared by several maps: the same filter is then stored once,
// whatever dimension refers to it (see Aggregator::filter_pool).

// -------------------------------------------------------------- one key ----
template <typename V>
class InternedMap {
public:
    using mapped_type = V;

    struct Item {
        std::string_view key;
        const V& value;
    };

    class const_iterator {
    public:
        const_iterator(const InternedMap* m, size_t i) : m_(m), i_(i) { skip(); }
        Item operator*() const {
            return Item{m_->pool_->view(m_->ids_[i_]), m_->values_[i_]};
        }
        const_iterator& operator++() { ++i_; skip(); return *this; }
        bool operator!=(const const_iterator& o) const { return i_ != o.i_; }
    private:
        void skip() {
            while (i_ < m_->ids_.size() && !m_->ids_[i_]) ++i_;
        }
        const InternedMap* m_;
        size_t i_;
    };

    const_iterator begin() const { return const_iterator(this, 0); }
    const_iterator end() const { return const_iterator(this, ids_.size()); }

    V& operator[](std::string_view key) {
        const uint32_t id = pool_->intern(key);
        if (ids_.empty()) rehash(64);
        const uint64_t h = StringPool::hash(key);
        size_t slot = find_slot(h, id);
        if (ids_[slot] == id) return values_[slot];
        if ((size_ + 1) * 10 >= ids_.size() * 7) {
            rehash(ids_.size() * 2);
            slot = find_slot(h, id);
        }
        ids_[slot] = id;
        ++size_;
        return values_[slot];
    }

    const V* find(std::string_view key) const {
        if (ids_.empty()) return nullptr;
        size_t slot = StringPool::hash(key) & mask_;
        while (ids_[slot]) {
            if (pool_->view(ids_[slot]) == key) return &values_[slot];
            slot = (slot + 1) & mask_;
        }
        return nullptr;
    }

    bool empty() const { return size_ == 0; }
    size_t size() const { return size_; }

    // Share a pool with other maps: the characters are then stored once.
    void use_pool(std::shared_ptr<StringPool> pool) { pool_ = std::move(pool); }

    // Entries only: a shared pool belongs to every map using it.
    void clear() {
        ids_.clear();
        values_.clear();
        size_ = 0;
        mask_ = 0;
    }

    // Deterministic order for the state writer (and for any caller that needs
    // the keys in order).  A pointer, not a reference: the vector must sort.
    struct Ref {
        std::string_view key;
        const V* value;
    };

    std::vector<Ref> sorted_by_key() const {
        std::vector<Ref> out;
        out.reserve(size_);
        for (const auto& it : *this) out.push_back(Ref{it.key, &it.value});
        std::sort(out.begin(), out.end(), [](const Ref& a, const Ref& b) {
            return a.key < b.key;
        });
        return out;
    }

private:
    size_t find_slot(uint64_t h, uint32_t id) const {
        size_t slot = h & mask_;
        while (ids_[slot] && ids_[slot] != id) slot = (slot + 1) & mask_;
        return slot;
    }

    void rehash(size_t n) {
        std::vector<uint32_t> old_ids(n, 0);
        std::vector<V> old_values(n);
        old_ids.swap(ids_);
        old_values.swap(values_);
        mask_ = n - 1;
        for (size_t i = 0; i < old_ids.size(); ++i) {
            if (!old_ids[i]) continue;
            size_t slot = StringPool::hash(pool_->view(old_ids[i])) & mask_;
            while (ids_[slot]) slot = (slot + 1) & mask_;
            ids_[slot] = old_ids[i];
            values_[slot] = std::move(old_values[i]);
        }
    }

    std::shared_ptr<StringPool> pool_ = std::make_shared<StringPool>();
    std::vector<uint32_t> ids_;
    std::vector<V> values_;
    size_t size_ = 0;
    size_t mask_ = 0;
};

// ------------------------------------------------------------- two keys ----
// (application, filter) pairs: two ids in the slot, and one pool holding both
// strings — a filter repeated across applications is stored once.
template <typename V>
class InternedPairMap {
public:
    using mapped_type = V;

    struct Item {
        std::string_view key1;
        std::string_view key2;
        const V& value;
    };

    class const_iterator {
    public:
        const_iterator(const InternedPairMap* m, size_t i) : m_(m), i_(i) { skip(); }
        Item operator*() const {
            return Item{m_->pool_->view(m_->ids1_[i_]), m_->pool_->view(m_->ids2_[i_]),
                        m_->values_[i_]};
        }
        const_iterator& operator++() { ++i_; skip(); return *this; }
        bool operator!=(const const_iterator& o) const { return i_ != o.i_; }
    private:
        void skip() {
            while (i_ < m_->ids1_.size() && !m_->ids1_[i_]) ++i_;
        }
        const InternedPairMap* m_;
        size_t i_;
    };

    const_iterator begin() const { return const_iterator(this, 0); }
    const_iterator end() const { return const_iterator(this, ids1_.size()); }

    V& operator()(std::string_view k1, std::string_view k2) {
        const uint32_t a = pool_->intern(k1);
        const uint32_t b = pool_->intern(k2);
        if (ids1_.empty()) rehash(64);
        const uint64_t h = StringPool::hash(k1) * 1099511628211ULL ^ StringPool::hash(k2);
        size_t slot = find_slot(h, a, b);
        if (ids1_[slot] == a && ids2_[slot] == b) return values_[slot];
        if ((size_ + 1) * 10 >= ids1_.size() * 7) {
            rehash(ids1_.size() * 2);
            slot = find_slot(h, a, b);
        }
        ids1_[slot] = a;
        ids2_[slot] = b;
        ++size_;
        return values_[slot];
    }

    bool empty() const { return size_ == 0; }
    size_t size() const { return size_; }

    // Share a pool with other maps: the characters are then stored once.
    void use_pool(std::shared_ptr<StringPool> pool) { pool_ = std::move(pool); }

    // Entries only: a shared pool belongs to every map using it.
    void clear() {
        ids1_.clear();
        ids2_.clear();
        values_.clear();
        size_ = 0;
        mask_ = 0;
    }

    // Deterministic order, and the grouping the "Filters per Application"
    // report needs: sorted by application, then by filter.
    struct Ref {
        std::string_view key1;
        std::string_view key2;
        const V* value;
    };

    std::vector<Ref> sorted_by_key() const {
        std::vector<Ref> out;
        out.reserve(size_);
        for (const auto& it : *this) out.push_back(Ref{it.key1, it.key2, &it.value});
        std::sort(out.begin(), out.end(), [](const Ref& a, const Ref& b) {
            if (a.key1 != b.key1) return a.key1 < b.key1;
            return a.key2 < b.key2;
        });
        return out;
    }

private:
    size_t find_slot(uint64_t h, uint32_t a, uint32_t b) const {
        size_t slot = h & mask_;
        while (ids1_[slot] && !(ids1_[slot] == a && ids2_[slot] == b))
            slot = (slot + 1) & mask_;
        return slot;
    }

    void rehash(size_t n) {
        std::vector<uint32_t> old1(n, 0), old2(n, 0);
        std::vector<V> old_values(n);
        old1.swap(ids1_);
        old2.swap(ids2_);
        old_values.swap(values_);
        mask_ = n - 1;
        for (size_t i = 0; i < old1.size(); ++i) {
            if (!old1[i]) continue;
            const uint64_t h = StringPool::hash(pool_->view(old1[i])) * 1099511628211ULL ^
                               StringPool::hash(pool_->view(old2[i]));
            size_t slot = h & mask_;
            while (ids1_[slot]) slot = (slot + 1) & mask_;
            ids1_[slot] = old1[i];
            ids2_[slot] = old2[i];
            values_[slot] = std::move(old_values[i]);
        }
    }

    std::shared_ptr<StringPool> pool_ = std::make_shared<StringPool>();
    std::vector<uint32_t> ids1_;
    std::vector<uint32_t> ids2_;
    std::vector<V> values_;
    size_t size_ = 0;
    size_t mask_ = 0;
};

// ---------------------------------------------------------------- accessors --
// Uniform view for the report helpers: (key, value) pairs whose keys and values
// are only borrowed, so printing a top-20 does not copy hundreds of thousands
// of strings.
template <typename V>
inline std::vector<std::pair<std::string_view, const V*>>
as_pairs(const InternedMap<V>& m) {
    std::vector<std::pair<std::string_view, const V*>> out;
    out.reserve(m.size());
    for (const auto& it : m) out.emplace_back(it.key, &it.value);
    return out;
}

template <typename V>
inline std::vector<std::pair<std::string_view, const V*>>
as_pairs(const std::map<std::string, V>& m) {
    std::vector<std::pair<std::string_view, const V*>> out;
    out.reserve(m.size());
    for (const auto& kv : m) out.emplace_back(kv.first, &kv.second);
    return out;
}
