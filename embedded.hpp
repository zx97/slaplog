// embedded.hpp
//
// GENERATED FILE — do not edit by hand.  The two literals below are spliced in by
// tools/gen_embedded.py from LICENSE and doc/slaplog.md; `make` regenerates them
// whenever either source changes, and `make check-doc` fails when this file is
// stale.  Editing a literal here loses the edit at the next build.

/* 
    SPDX-License-Identifier: AGPL-3.0-or-later
    GNU Affero General Public License v3.0 (https://www.gnu.org/licenses/agpl-3.0.txt)
    Copyright (c) 2026 Manuel FLURY
    All rights reserved.
    
    This file is part of slaplog - an OpenLDAP Log Analysis Tool.
    
    Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0-or-later).
    See the LICENSE file distributed with this work for full license text.
    
    THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL
    THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
    AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
    CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

// Contains embedded LICENSE and documentation content.

#ifndef EMBEDDED_HPP
#define EMBEDDED_HPP

#include <string>

namespace embedded {

    inline const std::string LICENSE_TEXT = R"EMBED(                    GNU AFFERO GENERAL PUBLIC LICENSE
                       Version 3, 19 November 2007

 Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.

                            Preamble

  The GNU Affero General Public License is a free, copyleft license for
software and other kinds of works, specifically designed to ensure
cooperation with the community in the case of network server software.

  The licenses for most software and other practical works are designed
to take away your freedom to share and change the works.  By contrast,
our General Public Licenses are intended to guarantee your freedom to
share and change all versions of a program--to make sure it remains free
software for all its users.

  When we speak of free software, we are referring to freedom, not
price.  Our General Public Licenses are designed to make sure that you
have the freedom to distribute copies of free software (and charge for
them if you wish), that you receive source code or can get it if you
want it, that you can change the software or use pieces of it in new
free programs, and that you know you can do these things.

  Developers that use our General Public Licenses protect your rights
with two steps: (1) assert copyright on the software, and (2) offer
you this License which gives you legal permission to copy, distribute
and/or modify the software.

  A secondary benefit of defending all users' freedom is that
improvements made in alternate versions of the program, if they
receive widespread use, become available for other developers to
incorporate.  Many developers of free software are heartened and
encouraged by the resulting cooperation.

  However, in the network server context, the GNU General Public License
permits making a modified version and letting the public access it on a
server without ever releasing its source code to the public.  The GNU
Affero General Public License is designed specifically to ensure that,
in such cases, the modified source code becomes available to the
community.  It requires the operator of a network server to provide the
source code of the modified version running there to the users of that
server.  Therefore, public use of a modified version, on a publicly
accessible server, gives the public access to the source code of the
modified version.

  An older license, called the Affero General Public License and
published by Affero, was designed to accomplish similar goals and is
published under a different license.  The GNU Affero General Public
License is not intended to be compatible with the Affero GPL, but
rather an effort to create a license that is compatible with the GPL
and the spirit of the original Affero GPL.

  The precise terms and conditions for copying, distribution and
modification follow.

                       TERMS AND CONDITIONS

  0. Definitions.

  "This License" refers to version 3 of the GNU Affero General Public License.

  "Copyright" also means copyright-like laws that apply to other kinds of
works, such as semiconductor masks.

  "The Program" refers to any copyrightable work licensed under this
License.  Each licensee is addressed as "you".  "Licensees" and
"recipients" may be individuals or organizations.

  To "modify" a work means to copy from or adapt all or part of the work
in a fashion requiring copyright permission, other than the making of an
exact copy.  The resulting work is called a "modified version" of the
earlier work or a work "based on" the earlier work.

  A "covered work" means either the unmodified Program or a work based
on the Program.

  To "propagate" a work means to do anything with it that, without
permission, would make you directly or secondarily liable for
infringement under applicable copyright law, except executing it on a
computer or modifying a private copy.  Propagation includes copying,
distribution (with or without modification), making available to the
public, and in some countries other activities as well.

  To "convey" a work means any kind of propagation that enables other
parties to make or receive copies.  Mere interaction with a user through
a computer network, with no transfer of a copy, is not conveying.

  An interactive user interface displays "Appropriate Legal Notices"
to the extent that it includes a convenient and prominently visible
feature that (1) displays an appropriate copyright notice, and (2)
tells the user that there is no warranty for the work (except to the
extent that warranties are provided), that licensees may convey the
work under this License, and how to view a copy of this License.  If
the interface presents a list of user commands or options, such as a
menu, a prominent item in the list meets this criterion.

  1. Source Code.

  The "source code" for a work means the preferred form of the work
for making modifications to it.  "Object code" means any non-source
form of a work.

  A "Standard Interface" means an interface that either is an official
standard defined by a recognized standards body, or, in the case of
interfaces specified for a particular programming language, one that
is widely used among developers working in that language.

  The "System Libraries" of an executable work include anything, other
than the work as a whole, that (a) is included in the normal form of
packaging a Major Component, but which is not part of that Major
Component, and (b) serves only to enable use of the work with that
Major Component, or to implement a Standard Interface for which an
implementation is available to the public in source code form.  A
"Major Component", in this context, means a major essential component
(kernel, window system, and so on) of the specific operating system
(if any) on which the executable work runs, or a compiler used to
produce the work, or an object code interpreter used to run it.

  The "Corresponding Source" for a work in object code form means all
the source code needed to generate, install, and (for an executable
work) run the object code and to modify the work, including scripts to
control those activities.  However, it does not include the work's
System Libraries, or general-purpose tools or generally available free
programs which are used unmodified in performing those activities but
which are not part of the work.  For example, Corresponding Source
includes interface definition files associated with source files for
the work, and the source code for shared libraries and dynamically
linked subprograms that the work is specifically designed to require,
such as by intimate data communication or control flow between those
subprograms and other parts of the work.

  The Corresponding Source need not include anything that users
can regenerate automatically from other parts of the Corresponding
Source.

  The Corresponding Source for a work in source code form is that
same work.

  2. Basic Permissions.

  All rights granted under this License are granted for the term of
copyright on the Program, and are irrevocable provided the stated
conditions are met.  This License explicitly affirms your unlimited
permission to run the unmodified Program.  The output from running a
covered work is covered by this License only if the output, given its
content, constitutes a covered work.  This License acknowledges your
rights of fair use or other equivalent, as provided by copyright law.

  You may make, run and propagate covered works that you do not
convey, without conditions so long as your license otherwise remains
in force.  You may convey covered works to others for the sole purpose
of having them make modifications exclusively for you, or provide you
with facilities for running those works, provided that you comply with
the terms of this License in conveying all material for which you do
not control copyright.  Those thus making or running the covered works
for you must do so exclusively on your behalf, under your direction
and control, on terms that prohibit them from making any copies of
your copyrighted material outside their relationship with you.

  Conveying under any other circumstances is permitted solely under
the conditions stated below.  Sublicensing is not allowed; section 10
makes it unnecessary.

  3. Protecting Users' Legal Rights From Anti-Circumvention Law.

  No covered work shall be deemed part of an effective technological
measure under any applicable law fulfilling obligations under article
11 of the WIPO copyright treaty adopted on 20 December 1996, or
similar laws prohibiting or restricting circumvention of such
measures.

  When you convey a covered work, you waive any legal power to forbid
circumvention of technological measures to the extent such circumvention
is effected by exercising rights under this License with respect to
the covered work, and you disclaim any intention to limit operation or
modification of the work as a means of enforcing, against the work's
users, your or third parties' legal rights to forbid circumvention of
technological measures.

  4. Conveying Verbatim Copies.

  You may convey verbatim copies of the Program's source code as you
receive it, in any medium, provided that you conspicuously and
appropriately publish on each copy an appropriate copyright notice;
keep intact all notices stating that this License and any
non-permissive terms added in accord with section 7 apply to the code;
keep intact all notices of the absence of any warranty; and give all
recipients a copy of this License along with the Program.

  You may charge any price or no price for each copy that you convey,
and you may offer support or warranty protection for a fee.

  5. Conveying Modified Source Versions.

  You may convey a work based on the Program, or the modifications to
produce it from the Program, in the form of source code under the
terms of section 4, provided that you also meet all of these conditions:

    a) The work must carry prominent notices stating that you modified
    it, and giving a relevant date.

    b) The work must carry prominent notices stating that it is
    released under this License and any conditions added under section
    7.  This requirement modifies the requirement in section 4 to
    "keep intact all notices".

    c) You must license the entire work, as a whole, under this
    License to anyone who comes into possession of a copy.  This
    License will therefore apply, along with any applicable section 7
    additional terms, to the whole of the work, and all its parts,
    regardless of how they are packaged.  This License gives no
    permission to license the work in any other way, but it does not
    invalidate such permission if you have separately received it.

    d) If the work has interactive user interfaces, each must display
    Appropriate Legal Notices; however, if the Program has interactive
    interfaces that do not display Appropriate Legal Notices, your
    work need not make them do so.

  A compilation of a covered work with other separate and independent
works, which are not by their nature extensions of the covered work,
and which are not combined with it such as to form a larger program,
in or on a volume of a storage or distribution medium, is called an
"aggregate" if the compilation and its resulting copyright are not
used to limit the access or legal rights of the compilation's users
beyond what the individual works permit.  Inclusion of a covered work
in an aggregate does not cause this License to apply to the other
parts of the aggregate.

  6. Conveying Non-Source Forms.

  You may convey a covered work in object code form under the terms
of sections 4 and 5, provided that you also convey the
machine-readable Corresponding Source under the terms of this License,
in one of these ways:

    a) Convey the object code in, or embodied in, a physical product
    (including a physical distribution medium), accompanied by the
    Corresponding Source fixed on a durable physical medium
    customarily used for software interchange.

    b) Convey the object code in, or embodied in, a physical product
    (including a physical distribution medium), accompanied by a
    written offer, valid for at least three years and valid for as
    long as you offer spare parts or customer support for that product
    model, to give anyone who possesses the object code either (1) a
    copy of the Corresponding Source for all the software in the
    product that is covered by this License, on a durable physical
    medium customarily used for software interchange, for a price no
    more than your reasonable cost of physically performing this
    conveying of source, or (2) access to copy the
    Corresponding Source from a network server at no charge.

    c) Convey individual copies of the object code with a copy of the
    written offer to provide the Corresponding Source.  This
    alternative is allowed only occasionally and noncommercially, and
    only if you received the object code with such an offer, in accord
    with subsection 6b.

    d) Convey the object code by offering access from a designated
    place (gratis or for charge), and offer equivalent access to the
    Corresponding Source in the same way through the same place at no
    further charge.  You need not require recipients to copy the
    Corresponding Source along with the object code.  If the place to
    copy the object code is a network server, the Corresponding Source
    may be on a different server (operated by you or a third party)
    that supports equivalent copying facilities, provided you maintain
    clear directions next to the object code saying where to find the
    Corresponding Source.  Regardless of what server hosts the
    Corresponding Source, you remain obligated to ensure that it is
    available for as long as needed to satisfy these requirements.

    e) Convey the object code using peer-to-peer transmission, provided
    you inform other peers where the object code and Corresponding
    Source of the work are being offered to the general public at no
    charge under subsection 6d.

  A separable portion of the object code, whose source code is excluded
from the Corresponding Source as a System Library, need not be
included in conveying the object code work.

  A "User Product" is either (1) a "consumer product", which means any
tangible personal property which is normally used for personal, family,
or household purposes, or (2) anything designed or sold for incorporation
into a dwelling.  In determining whether a product is a consumer product,
doubtful cases shall be resolved in favor of coverage.  For a particular
product received by a particular user, "normally used" refers to a
typical or common use of that class of product, regardless of the status
of the particular user or of the way in which the particular user
actually uses, or expects or is expected to use, the product.  A product
is a consumer product regardless of whether the product has substantial
commercial, industrial or non-consumer uses, unless such uses represent
the only significant mode of use of the product.

  "Installation Information" for a User Product means any methods,
procedures, authorization keys, or other information required to install
and execute modified versions of a covered work in that User Product from
a modified version of its Corresponding Source.  The information must
suffice to ensure that the continued functioning of the modified object
code is in no case prevented or interfered with solely because
modification has been made.

  If you convey an object code work under this section in, or with, or
specifically for use in, a User Product, and the conveying occurs as
part of a transaction in which the right of possession and use of the
User Product is transferred to the recipient in perpetuity or for a
fixed term (regardless of how the transaction is characterized), the
Corresponding Source conveyed under this section must be accompanied
by the Installation Information.  But this requirement does not apply
if neither you nor any third party retains the ability to install
modified object code on the User Product (for example, the work has
been installed in ROM).

  The requirement to provide Installation Information does not include a
requirement to continue to provide support service, warranty, or updates
for a work that has been modified or installed by the recipient, or for
the User Product in which it has been modified or installed.  Access to a
network may be denied when the modification itself materially and
adversely affects the operation of the network or violates the rules and
protocols for communication across the network.

  Corresponding Source conveyed, and Installation Information provided,
in accord with this section must be in a format that is publicly
documented (and with an implementation available to the public in
source code form), and must require no special password or key for
unpacking, reading or copying.

  7. Additional Terms.

  "Additional permissions" are terms that supplement the terms of this
License by making exceptions from one or more of its conditions.
Additional permissions that are applicable to the entire Program shall
be treated as though they were included in this License, to the extent
that they are valid under applicable law.  If additional permissions
apply only to part of the Program, that part may be used separately
under those permissions, but the entire Program remains governed by
this License without regard to the additional permissions.

  When you convey a copy of a covered work, you may at your option
remove any additional permissions from that copy, or from any part of
it.  (Additional permissions may be written to require their own
removal in certain cases when you modify the work.)  You may place
additional permissions on material, added by you to a covered work,
for which you have or can give appropriate copyright permission.

  Notwithstanding any other provision of this License, for material you
add to a covered work, you may (if authorized by the copyright holders of
that material) supplement the terms of this License with terms:

    a) Disclaiming warranty or limiting liability differently from the
    terms of sections 15 and 16 of this License; or

    b) Requiring preservation of specified reasonable legal notices or
    author attributions in that material or in the Appropriate Legal
    Notices displayed by works containing it; or

    c) Prohibiting misrepresentation of the origin of that material, or
    requiring that modified versions of such material be marked in
    reasonable ways as different from the original version; or

    d) Limiting the use for publicity purposes of names of licensors or
    authors of the material; or

    e) Declining to grant rights under trademark law for use of some
    trade names, trademarks, or service marks; or

    f) Requiring indemnification of licensors and authors of that
    material by anyone who conveys the material (or modified versions of
    it) with contractual assumptions of liability to the recipient, for
    any liability that these contractual assumptions directly impose on
    those licensors and authors.

  All other non-permissive additional terms are considered "further
restrictions" within the meaning of section 10.  If the Program as you
received it, or any part of it, contains a notice stating that it is
governed by this License along with a term that is a further
restriction, you may remove that term.  If a license document contains
a further restriction but permits relicensing or conveying under this
License, you may add to a covered work material governed by the terms
of that license document, provided that the further restriction does
not survive such relicensing or conveying.

  If you add terms to a covered work in accord with this section, you
must place, in the relevant source files, a statement of the
additional terms that apply to those files, or a notice indicating
where to find the applicable terms.

  Additional terms, permissive or non-permissive, may be stated in the
form of a separately written license, or stated as exceptions;
the above requirements apply either way.

  8. Termination.

  You may not propagate or modify a covered work except as expressly
provided under this License.  Any attempt otherwise to propagate or
modify it is void, and will automatically terminate your rights under
this License (including any patent licenses granted under the third
paragraph of section 11).

  However, if you cease all violation of this License, then your
license from a particular copyright holder is reinstated (a)
provisionally, unless and until the copyright holder explicitly and
finally terminates your license, and (b) permanently, if the copyright
holder fails to notify you of the violation by some reasonable means
prior to 60 days after the cessation.

  Moreover, your license from a particular copyright holder is
reinstated permanently if the copyright holder notifies you of the
violation by some reasonable means, this is the first time you have
received notice of violation of this License (for any work) from that
copyright holder, and you cure the violation prior to 30 days after
your receipt of the notice.

  Termination of your rights under this section does not terminate the
licenses of parties who have received copies or rights from you under
this License.  If your rights have been terminated and not permanently
reinstated, you do not qualify to receive new licenses for the same
material under section 10.

  9. Acceptance Not Required for Having Copies.

  You are not required to accept this License in order to receive or
run a copy of the Program.  Ancillary propagation of a covered work
occurring solely as a consequence of using peer-to-peer transmission
to receive a copy likewise does not require acceptance.  However,
nothing other than this License grants you permission to propagate or
modify any covered work.  These actions infringe copyright if you do
not accept this License.  Therefore, by modifying or propagating a
covered work, you indicate your acceptance of this License to do so.

  10. Automatic Licensing of Downstream Recipients.

  Each time you convey a covered work, the recipient automatically
receives a license from the original licensors, to run, modify and
propagate that work, subject to this License.  You are not responsible
for enforcing compliance by third parties with this License.

  An "entity transaction" is a transaction transferring control of an
organization, or substantially all assets of one, or subdividing an
organization, or merging organizations.  If propagation of a covered
work results from an entity transaction, each party to that
transaction who receives a copy of the work also receives whatever
licenses to the work the party's predecessor in interest had or could
give under the previous paragraph, plus a right to possession of the
Corresponding Source of the work from the predecessor in interest, if
the predecessor has it or can get it with reasonable efforts.

  You may not impose any further restrictions on the exercise of the
rights granted or affirmed under this License.  For example, you may
not impose a license fee, royalty, or other charge for exercise of
rights granted under this License, and you may not initiate litigation
(including a cross-claim or counterclaim in a lawsuit) alleging that
any patent claim is infringed by making, using, selling, offering for
sale, or importing the Program or any portion of it.

  11. Patents.

  A "contributor" is a copyright holder who authorizes use under this
License of the Program or a work on which the Program is based.  The
work thus licensed is called the contributor's "contributor version".

  A contributor's "essential patent claims" are all patent claims
owned or controlled by the contributor, whether already acquired or
hereafter acquired, that would be infringed by some manner, permitted
by this License, of making, using, or selling its contributor version,
but do not include claims that would be infringed only as a
consequence of further modification of the contributor version.  For
purposes of this definition, "control" includes the right to grant
patent sublicenses in a manner consistent with the requirements of
this License.

  Each contributor grants you a non-exclusive, worldwide, royalty-free
patent license under the contributor's essential patent claims, to
make, use, sell, offer for sale, import and otherwise run, modify and
propagate the contents of its contributor version.

  In the following three paragraphs, a "patent license" is any express
agreement or commitment, however denominated, not to enforce a patent
(such as an express permission to practice a patent or covenant not to
sue for patent infringement).  To "grant" such a patent license to a
party means to make such an agreement or commitment not to enforce a
patent against the party.

  If you convey a covered work, knowingly relying on a patent license,
and the Corresponding Source of the work is not available for anyone
to copy, free of charge and under the terms of this License, through a
publicly available network server or other readily accessible means,
then you must either (1) cause the Corresponding Source to be so
available, or (2) arrange to deprive yourself of the benefit of the
patent license for this particular work, or (3) arrange, in a manner
consistent with the requirements of this License, to extend the patent
license to downstream recipients.  "Knowingly relying" means you have
actual knowledge that, but for the patent license, your conveying the
covered work in a country, or your recipient's use of the covered work
in a country, would infringe one or more identifiable patents in that
country that you have reason to believe are valid.

  If, pursuant to or in connection with a single transaction or
arrangement, you convey, or propagate by procuring conveyance of, a
covered work, and grant a patent license to some of the parties
receiving the covered work authorizing them to use, propagate, modify
or convey a specific copy of the covered work, then the patent license
you grant is automatically extended to all recipients of the covered
work and works based on it.

  A patent license is "discriminatory" if it does not include within
the scope of its coverage, prohibits the exercise of, or is
conditioned on the non-exercise of one or more of the rights that are
specifically granted under this License.  You may not convey a covered
work if you are a party to an arrangement with a third party that is
in the business of distributing software, under which you make payment
to the third party based on the extent of your activity of conveying
the work, and under which the third party grants, to any of the
parties who would receive the covered work from you, a discriminatory
patent license (a) in connection with copies of the covered work
conveyed by you (or copies made from those copies), or (b) primarily
for and in connection with specific products or compilations that
contain the covered work, unless you entered into that arrangement,
or that patent license was granted, prior to 28 March 2007.

  Nothing in this License shall be construed as excluding or limiting
any implied license or other defenses to infringement that may be
otherwise available to you under applicable patent law.

  12. No Surrender of Others' Freedom.

  If conditions are imposed on you (whether by court order, agreement or
otherwise) that contradict the conditions of this License, they do not
excuse you from the conditions of this License.  If you cannot convey a
covered work so as to satisfy simultaneously your obligations under this
License and any other pertinent obligations, then as a consequence you may
not convey it at all.  For example, if you agree to terms that obligate you
to collect a royalty for further conveying from those to whom you convey
the Program, the only way you could satisfy both those terms and this
License would be to refrain entirely from conveying the Program.

  13. Remote Network Interaction; Use with the GNU General Public License.

  Notwithstanding any other provision of this License, if you modify the
Program, your modified version must prominently offer all users
interacting with it remotely through a computer network (if your version
supports such interaction) an opportunity to receive the Corresponding
Source of your version by providing access to the Corresponding Source
from a network server at no charge, through some standard or customary
means of facilitating copying of software.  This Corresponding Source
shall include the Corresponding Source for any work covered by version 3
of the GNU General Public License that is incorporated pursuant to the
following paragraph.

  Notwithstanding any other provision of this License, you have
permission to link or combine any covered work with a work licensed
under version 3 of the GNU General Public License into a single
combined work, and to convey the resulting work.  The terms of this
License will continue to govern the part which is the covered work,
but the work with which it is combined will remain governed by version
3 of the GNU General Public License.

  14. Revised Versions of this License.

  The Free Software Foundation may publish revised and/or new versions of
the GNU Affero General Public License from time to time.  Such new versions
will be similar in spirit to the present version, but may differ in detail to
address new problems or concerns.

  Each version is given a distinguishing version number.  If the
Program specifies that a certain numbered version of the GNU Affero
General Public License "or any later version" applies to it, you have
the option of following the terms and conditions either of that
numbered version or of any later version published by the Free
Software Foundation.  If the Program does not specify a version number
of the GNU Affero General Public License, you may choose any version
ever published by the Free Software Foundation.

  If the Program specifies that a proxy can decide whether future
versions of the GNU Affero General Public License can be used, that
proxy's public statement of acceptance of a version permanently
authorizes you to choose that version for the Program.

  Later license versions may give you additional or different
permissions.  However, no additional obligations are imposed on any
author or copyright holder as a result of your choosing to follow a
later version.

  15. Disclaimer of Warranty.

  THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY
APPLICABLE LAW.  EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT
HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY
OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE.  THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM
IS WITH YOU.  SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF
ALL NECESSARY SERVICING, REPAIR OR CORRECTION.

  16. Limitation of Liability.

  IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MODIFIES AND/OR CONVEYS
THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES, INCLUDING ANY
GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE
USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED TO LOSS OF
DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD
PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER PROGRAMS),
EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF
SUCH DAMAGES.

  17. Interpretation of Sections 15 and 16.

  If the disclaimer of warranty and limitation of liability provided
above cannot be given local legal effect according to their terms,
reviewing courts shall apply local law that most closely approximates
an absolute waiver of all civil liability in connection with the
Program, unless a warranty or assumption of liability accompanies a
copy of the Program in return for a fee.

            END OF TERMS AND CONDITIONS

            How to Apply These Terms to Your New Programs

  If you develop a new program, and you want it to be of the greatest
possible use to the public, the best way to achieve this is to make it
free software which everyone can redistribute and change under these terms.

  To do so, attach the following notices to the program.  It is safest
to attach them to the start of each source file to most effectively
state the exclusion of warranty; and each file should have at least
the "copyright" line and a pointer to where the full notice is found.

    <one line to give the program's name and a brief idea of what it does.>
    Copyright (C) <year>  <name of author>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

Also add information on how to contact you by electronic and paper mail.

  If your software can interact with users remotely through a computer
network, you should also make sure that it provides a way for users to
get its source.  For example, if your program is a web application, its
interface could display a "Source" link that leads users to an archive
of the code.  There are many ways you could offer source, and different
solutions will be better for different programs; see section 13 for the
specific requirements.

  You should also get your employer (if you work as a programmer) or school,
if any, to sign a "copyright disclaimer" for the program, if necessary.
For more information on this, and how to apply and follow the GNU AGPL, see
<https://www.gnu.org/licenses/>.
)EMBED";

    inline const std::string DOCUMENTATION_TEXT = R"EMBED(# slaplog — OpenLDAP Access Log Analyzer

**SPDX-License-Identifier:** AGPL-3.0-or-later  
**License:** GNU Affero General Public License v3.0 (https://www.gnu.org/licenses/agpl-3.0.txt)  
**Version:** 4.0.5  
**Author:** Manuel FLURY  
**Copyright:** © 2026 Manuel FLURY. All rights reserved.

See the [CHANGELOG](../CHANGELOG.md) for the release history.

This file is part of slaplog - an OpenLDAP Log Analysis Tool.

Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0-or-later).
See the LICENSE file distributed with this work for full license text.

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---

## Table of Contents

1. [Overview](#overview)
2. [Supported Log Formats](#supported-log-formats)
3. [Build & Install](#build--install)
4. [Usage](#usage)
5. [Command-Line Options](#command-line-options)
6. [Report Sections](#report-sections)
7. [Output Formats](#output-formats)
8. [Session Tracking](#session-tracking)
9. [Architecture](#architecture)
10. [File-by-File Guide](#file-by-file-guide)
11. [Extending the Parser](#extending-the-parser)

---

## Overview

`slaplog` is a command-line tool that parses OpenLDAP `slapd` access logs and
produces structured reports in text (with ANSI color), HTML, JSON, or replay
format (for jMeter/LoadRunner).

It is designed to handle large log volumes (multi-GB, thousands of files) by
processing files in parallel with a bounded worker pool (`-j`, default CPU
cores − 1, never more than the file count). Each worker owns the `Aggregator`
for the file it is reading and folds it into the shared result under a single
mutex, so parsing itself never contends.

Key features:

- **Multi-format support**: Parses all OpenLDAP log formats (debug, syslog-utc,
  syslog-localtime, rfc3339-utc, ol26, rfc3339, syslog) with automatic per-line
  detection, supporting mixed formats in a single file.
- **Replay output format**: Pipe-delimited single-line operations for
  jMeter/LoadRunner replay with configurable separators.
- **Configurable date output**: Reports can output timestamps in rfc3339, iso8601,
  syslog, epoch, or preserve original format.
- Recognises all standard LDAP operations: BIND, SRCH, ADD, DEL, MOD, MODRDN,
  CMP, EXT, ABANDON, UNBIND, and RESULTS.
- Tracks connection state (ACCEPT, CLOSED, TLS), replication CSN events,
  session tracking control, and extended operations.
- Detects server start/stop events from log lines.
- Collects detailed per-operation metrics: execution time (etime), queue time
  (qtime), error codes, search base, filter, attributes, and who performed the
  operation.
- Session tracking correlation: maps NAT'd ACCEPT IPs to real client IPs via
  the OpenLDAP session tracking request control `[IP=... NAME=... USERNAME=...]`.
- **Cluster aggregation**: the logs of several servers (same period, or periods
  that overlap) are analysed into a single global picture, with the load split
  back per server.  A connection is keyed by *(server, conn)*, so two servers
  that both number their connections from 1 are never merged into one.
- **Bind usage**: how clients authenticated — method (simple / SASL /
  anonymous), the transport the bind ran over (ldaps / ldap + StartTLS / plain
  ldap), the SASL mechanism, and whether the session-tracking control was used.
- Top-N slowest operations and busiest connections.
- Indexing diagnostics, question-mark filter analysis, global control warnings.
- Section filtering (`-s`) to show only the parts of the report you need.
- Compact mode for top-5 summaries.
- Unknown-line collection for diagnosing log lines the parser does not yet
  handle.

## Supported Log Formats

slaplog supports all OpenLDAP log formats with automatic per-line detection:

| Format | Example | Description |
|--------|---------|-------------|
| `auto` | (default) | Tries all formats per line, supports mixed formats in a single file |
| `debug` | `411d2b6a.1f4b2c3a 0x7f9c1e33a700` | Hex timestamp + thread ID |
| `syslog-utc` | `Aug  5 14:23:01` | Syslog format in UTC |
| `syslog-localtime` | `Aug  5 14:23:01` | Syslog format in local time |
| `rfc3339-utc` | `2026-08-05T14:23:01.123456Z` | RFC3339 UTC with fractional seconds |
| `ol26` | `[2026-08-05T14:23:01.123Z]` | Bracket-style timestamp |
| `rfc3339` | `2026-08-05T14:23:01Z` | Generic RFC3339 |
| `syslog` | `Aug  5 14:23:01` | Generic syslog |

Use `--log-format` to specify a fixed format for faster parsing when you know all lines share the same format.

If a line does not match any header format, it is marked as `UNKNOWN_LINE` and
collected for diagnostic output.

## Build & Install

### Requirements

- C++17 compiler — GCC 8+ (GCC 11+ recommended)
- POSIX threads
- Development libraries: `zlib`, `bzip2`, `lzma` (for compressed log files)
- `nlohmann/json` header (system package — see below)

Install dependencies for your distro:

| Distro | Command |
|--------|---------|
| Fedora / RHEL 9+ | `sudo dnf install gcc-c++ zlib-devel bzip2-devel xz-devel json-devel` |
| RHEL 8 (EPEL)    | `sudo dnf install gcc-toolset-12-gcc-c++ zlib-devel bzip2-devel xz-devel json-devel` |
| Debian / Ubuntu  | `sudo apt install g++ zlib1g-dev libbz2-dev liblzma-dev nlohmann-json3-dev` |
| Arch Linux       | `sudo pacman -S gcc zlib bzip2 xz nlohmann-json` |

### Build

```bash
cd slaplog
make
```

The Makefile auto-increments a build number on each compilation.

### Clean

```bash
make clean
```

### Tests

```bash
make test        # dependency-free: perf and TZ guards (shell + the binary)
make test-ui     # the jsdom/WebAssembly harnesses (needs node, and `make wasm`)
make check       # check-doc + make test
```

`make test-ui` needs jsdom: `npm install --prefix tests`. The suite lives in
`tests/`, is tracked, and compares the native report against the WebAssembly one
byte for byte.

### WebAssembly build (browser)

slaplog can also be compiled to WebAssembly, so a log file can be analysed
**entirely inside a browser tab** — the file never leaves the machine. Several
files can be dropped at once, and a **whole folder can be added**: it is walked
recursively, which is how a cluster's logs are gathered in one gesture
(`logs/*/access.log`). Selections add up, and a file is identified by its path
*inside* the selection rather than by its name — a folder holding one
identically named `access.log` per server directory would otherwise lose all but
the first.  Each file in the list carries its own **remove** button, so a file
picked by mistake comes back out of the selection without starting over.
The files are analysed sequentially and aggregated into a single report, with a
progress indicator.

**Live build:** <https://slaplog.pages.dev/>

```bash
make wasm                                   # -> wasm/web/slaplog.js + slaplog.wasm
python3 -m http.server -d wasm/web 8000     # then open http://localhost:8000/
```

This requires the [Emscripten SDK](https://emscripten.org/) (`em++` on the
`PATH`). zlib and bzip2 come from Emscripten's own ports; liblzma is cross-built
once by `wasm/build_liblzma.sh`. The target is fully separate from the native
build, which is left untouched. See `wasm/README.md` for the architecture and
for the ordering details that differ from earlier releases.

## Usage

```bash
slaplog [options] <logfile|directory> [file|dir ...]
```

### Basic Examples

Parse a single log file and print a color report:

```bash
slaplog /var/log/slapd/access.log
```

Parse all log files in a directory recursively:

```bash
slaplog -r /var/log/slapd/
```

Generate an HTML report:

```bash
slaplog -o html /var/log/slapd/access.log > report.html
```

Show only the statistics and session tracking sections:

```bash
slaplog -s stats,sessions /var/log/slapd/access.log
```

Analyze only recent logs without a progress bar (batch / cron friendly):

```bash
# Only files modified in the last 7 days, no progress bar
slaplog -q -m 7 -r /var/log/slapd/

# Only the 5 most recently modified files
slaplog -q -n 5 -r /var/log/slapd/
```

The `-n/--max-files` and `-m/--mtime` filters apply to files discovered when
scanning directories; they are based on each file's last-modification time.
When both are combined, the `--mtime` window is applied first, then the
`--max-files` limit keeps the newest survivors.

Write unknown lines to a file (and still produce the report):

```bash
slaplog --unknown-lines unknown.txt /var/log/slapd/access.log
```

## Command-Line Options

| Option | Description |
|--------|-------------|
| `-o, --output FORMAT` | Output format: `text` (plain), `textcolor` (ANSI, default), `html`, `tabhtml` (same report in tabs), `json`, `replay` |
| `-c, --compact` | Show top 5 instead of top 20 for ranked sections |
| `-r, --recursive` | Recurse into directories when collecting log files |
| `-q, --quiet` | Suppress the progress bar on stderr (useful for batch / cron runs) |
| `-n, --max-files N` | Analyze only the `N` most recently modified files in a directory scan |
| `-m, --mtime DAYS` | Analyze only files modified within the last `DAYS` days (like `find -mtime`) |
| `-j, --jobs N` | Worker thread count (default: CPU cores - 1) |
| `-s, --section LIST` | Comma-separated list of sections to display (see below) |
| `--log-format FORMAT` | Input log format: `auto` (default), `debug`, `syslog-utc`, `syslog-localtime`, `rfc3339-utc`, `ol26`, `rfc3339`, `syslog` |
| `--output-date-format FMT` | Output date format in reports: `rfc3339` (default), `iso8601`, `syslog`, `epoch`, `preserve` |
| `--replay-separator SEP` | Delimiter for replay output (default: `\|`). Use `tab` for tabulation, `comma` for CSV |
| `--replay-limit N` | Max operations written to the replay temp file (default: `1000000`, `0` = unlimited). Acts as a safety cap; a warning is printed when ops are dropped. |
| `--unknown-lines FILE` | Write unrecognised lines to FILE, then generate the full report |
| `--unknown-lines-only FILE` | Like `--unknown-lines` but skip the report |
| `--no-graph` | Omit the charts from the `html` report (they are drawn by default) |
| `--no-version` | Omit the engine name and version from the `html` report footer |
| `--title TITLE` | Custom subtitle for the rendered reports (text, HTML), appended after the default one, separated by ` - `.  Ignored by `json` and `replay`, whose schemas are fixed. |
| `-d, --debug` | Print debug information (file count, parsing details, per-file traces) |
| `-D, --documentation` | Print full documentation to stdout |
| `-h, --help` | Show help message |
| `-V, --version` | Show version and build info |

### Section Names (`-s`)

All sections are included by default (`-s all`). Use `-s section1,section2,...`
to select specific sections:

| Section | Content |
|---------|---------|
| `stats` | Processing time, line counts, connection stats, time range |
| `load` | Per-server load: operations, cumulative etime, connections (cluster aggregation) |
| `ops` | Per-operation type counts (BIND, SRCH, RESULT, etc.) |
| `bind` | Bind usage: authentication method, transport (ldap/ldaps/StartTLS), SASL mechanism |
| `errors` | Error code distribution with LDAP error names |
| `errors_per_app` | Errors broken down by application identity |
| `paged` | Searches using the pagedResultsControl (by shape, or the control line at loglevel `trace`) |
| `bases` | Top search bases by count and cumulative etime |
| `filters` | Top search filters by count, etime, nentries=1/0 |
| `wildcards` | Filters containing wildcards (also included with `filters`) |
| `filters_per_app` | Filters broken down by application identity |
| `attrs` | Most frequently requested attributes |
| `apps` | Top applications by operation count and etime |
| `extops` | Extended Operation OIDs and Global Control warnings |
| `qmark` | Question-mark filter `(?attr=...)` analysis |
| `csn` | CSN internal replication events (get/queue/graduate) |
| `server` | Server start, stop, and shutdown events |
| `index` | Indexing diagnostics (not-indexed attributes) |
| `sessions` | Session Tracking correlation table |
| `topops` | Top 100 slowest operations (by etime) |
| `topconns` | Top 100 busiest connections (by cumulative etime) |

## Report Sections Detail

### Statistics

Shows processing performance, total/unknown lines, connection counts, peak
active connections (for a run that mixes several servers, the peak of their
*sum* — the busiest moment — not the busiest server), time range, total
etime/qtime, and read/write balance.  The
**server(s)** the log lines name are listed too — read from the syslog/rfc3339
header prefix, so a log taken with the *debug* format (which names no host)
carries none and the row is simply absent.  The HTML report lays these metrics
out **two per row**, because the section holds little data and a single column
would make it far taller than it needs to be.

### Load by Server

The one section that only means something when the logs of **several servers**
are analysed together — a cluster, a load-balanced pair, a set of rotated files
collected from each node.  It is drawn only when the log names more than one
server; the JSON always carries the per-server totals, since that output is
data rather than a rendered report.

Each file is parsed independently and its counters summed, so a run over the
whole set yields one global picture; this section splits that picture back
across the servers the log lines name:

| Column | Meaning |
|--------|---------|
| Server | The hostname in the syslog/rfc3339 header of the lines |
| Operations | Completed operations (result lines) attributed to that server |
| Share | That server's part of the total operation count |
| Total etime | Cumulative execution time of its operations |
| Connections | Connections opened on it (`ACCEPT`) |
| Results | Result lines it produced |

A connection's identity is **(server, conn)**, not the connection number alone:
every server in a cluster numbers its connections from 1, so `conn=1` on two
servers is two different connections.  Keying on the number alone — as a
single-server analysis can — would merge them into one and corrupt the
per-connection figures (top connections, session correlation, paged runs).  When
the log names more than one server, the *Top Connections* table therefore gains
a **server** column so a connection number can be attributed to the right node;
a single-server log, where the number is already unambiguous, keeps its
narrower table.  The *replay* format keeps its fixed schema, in which `conn` is
per-server: a replay run over a cluster should be split by server.

The *debug* log format names no host, so it contributes nothing here and the
section is absent — that format describes one server, and there is nothing to
split.

Each server's own coverage is also part of this picture: the parser keeps the
earliest and the latest timestamped line seen from each host, the report prints
them as the **coverage lanes** under the two time-series charts, and the JSON
carries them as `time_by_server` next to `load_by_server`.

### Operation Counts

Counts per operation type: BIND, BIND ANONYMOUS, EXT, ADD, DEL, MOD, MODRDN,
CMP, SRCH, SRCH ATTR, RESULT, SEARCH RESULT, ABANDON, UNBIND, TLS, SASL,
GLOBAL_CONTROL, SYNCPROV, CSN_GET/QUEUE/GRADUATE, NOT_INDEXED, STARTTLS.

### Bind Usage

How clients authenticated, from the `BIND` request lines.  Three cuts of the
same set of binds:

**Authentication method** — the method slapd decoded and logged:

| `method=` | Meaning |
|-----------|---------|
| `128` (0x80) | The simple method.  A simple bind with an **empty DN** is counted as *anonymous*, not *simple* |
| `163` (0xa3) | SASL |
| `0` | The anonymous-demotion line (`BIND anonymous mech=implicit …`) |

**Transport** — read from the connection's state at the moment of the bind, so
it is the transport that bind actually ran over:

| Value | How it is recognised |
|-------|----------------------|
| `ldaps` | A `TLS established` line and **no** STARTTLS on the connection (implicit TLS) |
| `ldap + StartTLS` | A `TLS established` line **after** a `STARTTLS` operation on the connection |
| `ldap` | No `TLS established` at all |

A bind that runs *before* the STARTTLS operation is counted as `ldap`, which is
what it was: the credentials crossed in the clear, whatever happened later.

**SASL mechanism** — the mechanism slapd names when a bind succeeds
(`EXTERNAL`, `PLAIN`, …).  `SIMPLE` and `implicit` are not listed: the first is
the simple method already counted above, the second the anonymous demotion.

The section also reports how many bind requests carried the **session-tracking
control**, and draws a donut of the method mix whose footnote gives the share of
binds that ran over TLS.

### LDAP Result Codes

Every LDAP result code with its human-readable name and count.  A code does not
say *error or not*: it points at who is at fault — or, for one class, says the
log cannot tell — and only the server-side class says anything about the
directory's health.  Rows, table cells and charts are coloured by class:

| Colour | Class | What it means | Codes |
|--------|-------|---------------|-------|
| green | informational | the operation did what was asked, or the protocol is progressing | `0`, `5`, `6`, `10`, `14` |
| amber | client-side | the request, the identity or the data were at fault; slapd answered correctly | `2`, `7`, `16`–`21`, `32`, `34`, `48`, `49`, `64`–`69` |
| violet | by configuration | the server refused or limited **by configuration** — a numeric limit it was told to enforce, which the client is told about and can page or split around | `3`, `4`, `11` |
| amber over violet, hatched | by configuration, or client-side | the same "no", but the log cannot say which side should have known better: a request the client had no right to make and one it legitimately expected to work are refused with the very same code | `8`, `13`, `50`, `53` |
| red | server-side | slapd itself: internal error, overload, unavailable backend, broken alias | `1`, `12`, `33`, `36`, `51`, `52`, `54`, `71`, `80` |

The five lists cover the whole mnemonic table, so no code is left unclassified;
a code outside it is reported server-side (and named `unknown`) rather than
guessed into a harmless class.  The informational codes are recalled in a note
above the table, and left out of the two charts that show *failures*.

The *by configuration, or client-side* class is drawn **hatched** — amber
diagonal stripes over the violet base — because the result code alone does not
say who should have done otherwise.
`53 unwillingToPerform` is the clearest case: OpenLDAP returns it when it refuses
by policy (a referral it will not follow, TLS that is required, a password-policy
outcome), and the same code answers a client that had no business asking and a
client whose legitimate request stumbles on the configuration.  `50
insufficientAccessRights` is the same question asked of an ACL: a genuine
"no" to an overreaching client, or an ACL that is too tight.  The class says
*look at the request*, not *someone is guilty* — and unlike the numeric limits
(`3`, `4`, `11`), nothing in the result tells the client it could have avoided
the refusal.

### Paged Searches

Searches that carried the **pagedResultsControl** (`1.2.840.113556.1.4.319`),
with the count broken down by the identity that issued them.  Two independent
ways are used, and either may find one:

1. **By shape** — a paged search repeats the same request on one connection, and
   every page returns the same number of entries until the last, which is
   smaller: that is the end of the result set.  On the reference log this is the
   only way, because the log was taken at `loglevel stats`.
2. **By the control line** — at `loglevel trace`, slapd logs every control a
   request carries:

```
=> get_ctrls: oid="1.2.840.113556.1.4.319" (critical)
```

That line carries no `conn=`, so the control is attributed to the connection of
the next line that names one — normally the `SRCH` that asked for it.

The shape is a match, not a proof.  Two cases it gets wrong, in opposite
directions: an application that repeats one search and then stops has exactly
this shape, so a counted run is an *upper bound* on the real number of paged
searches; and a result set whose size is an exact multiple of the page size ends
on a full page, leaving every count equal, so a real paged walk of that shape is
*not* counted.  A run is closed when the parameters change, a non-search
operation completes, or the connection ends.

On the 1 GiB reference log the count is **zero**, and that is the honest answer
rather than a failure of the method: its busiest searching connection interleaves
a `SRCH` with a `DEL` (a uid lookup before a delete), so every run is one search
long, and the rest query a different uid each time.  No connection there repeats
one identical request, which is what a paged walk does.

### Search Analysis

- **Bases**: Top search base DNs by frequency and cumulative execution time.
- **Filters**: Top filters by frequency and cumulative etime, plus analysis of
  filters returning exactly 1 or 0 entries.
- **Wildcard filters**: Filters containing `*` (substring searches).
- **Filters per app**: Which applications use which filters.
- **Attributes**: Most frequently requested attributes in search results.

### Application Profiling

Each connection is identified by its BIND DN, authcid/authzid, or session
tracking username/name. The report shows which applications are most active
and which consume the most server time.

### Extended Operations

OIDs and names of all extended operations used (StartTLS, PasswordModify,
WhoAmI, Cancel, etc.), plus unrecognised global control OIDs.

### Session Tracking Correlations

When OpenLDAP's session tracking request control is enabled, slapd logs
`[IP=... NAME=... USERNAME=...]` blocks on operation lines. The table is
**grouped by client** and sorted by session count, because the tracking name
usually carries a per-session identifier that would otherwise make every row
unique:

- **Sessions**: Number of sessions seen for this client.
- **NAT IPs**: Number of distinct NAT addresses it connected from.
- **Real IP**: The actual client IP from the session tracking control.
- **Name**: Client identifier (hostname, pod name, …), with a trailing session
  id such as `…=sessionId-1792207915730` stripped so that sessions group.
- **Username**: Application username or DN.
- **BIND dn**: The DN used to authenticate on this connection.

Correlation entries are keyed by `(restart_epoch, conn)` so that connections
are correctly isolated across slapd restarts (where the connection ID counter
resets).

### Top Operations & Connections

The 100 slowest individual operations and the 100 most expensive connections
by cumulative execution time. Each shows the connection, operation, who,
search base/filter, and error code.

## Output Formats

### Text (`-o text`)

Plain monochrome output suitable for terminal pipes, file logging, or
environments without ANSI support.

### Textcolor (`-o textcolor`, default)

Same layout as text but with ANSI escape sequences for:
- Section headers in cyan bold
- Metric labels in green
- Etime values color-coded: green (<0.1s), cyan (<0.5s), yellow (<1s),
  red (<5s), bright red (≥5s)
- Error codes color-coded by class: green for information, amber for
  client-side, magenta for what the configuration refused, red for slapd's own
  failures — and a colour key printed above the table.  The dual class shares
  the magenta: ANSI has no hatch, and the text report names no class, so it is
  the HTML side that draws the "either cause" reading
- Alternating application colors in filters-per-app table
- Count gradient: green → yellow → red → bright red

### HTML (`-o html`)

Standalone HTML page with embedded CSS featuring:
- Blue gradient header
- Flexbox meta information bar
- Rounded tables with hover highlighting and alternating row colors
- Server events with green (start) / red (stop) left border indicators
- Color-coded etime values
- Responsive layout (`@media` query for mobile)
- **A floating section index**, fixed in the top-right corner: it lists every
  section the report actually drew (charts are not sections) and scrolls to it
  on click.  It opens with the report, so the reader sees where he can go, then
  tucks itself away into a three-line window on the section being read — the one
  before, the one read, the one after — which it keeps up to date as the report
  is scrolled.  It opens again as the pointer comes near, and a click on the
  heading pins it open, so it is also usable without a pointer (touch,
  keyboard); the change of height is animated, and the box is clipped rather
  than rebuilt, so its width never moves.  The links are built from the page
  itself, so the index can never offer a section that is not there.
- **Every table can be sorted by a column.**  A click on a header sorts by that
  column and a small arrow shows the direction; a second click reverses it, and
  only the column in use carries an arrow.  Numbers are compared as numbers
  (counts, durations, shares), anything else as text (`user2` before `user10`),
  and a long table's *show N more* fold follows the sorted order.  *Statistics*
  is label/value pairs rather than columns, so it is left alone.
- **Ten inline SVG charts**, each placed under the section it summarises —
  drawn by default, disable with `--no-graph`.  None of them carries a
  *"How to read it"* note.  A note under a drawing that needs no explaining (a
  share ring, a connection curve, a pie) is noise, and a note that talks past the
  thing the reader is stuck on is worse than none.  Where a word really is needed,
  it belongs in the chart's subtitle — which is where every one of them now says
  what it shows:
  - *Simultaneous Connections*: how many connections were open across the
    analysed time range, with a marker on every server start/stop event, a
    shaded band over each downtime period, and an orange marker for a restart
    that had no shutdown before it (a likely crash).  Under the time axis sits
    one **lane per server**: the faint track is the window the chart plots and
    the coloured span is the window that server's own log actually covers, so a
    curve that steps up and then falls off a cliff is read as the end of a file
    instead of the end of a heavy operation.  A single server gets no lane — its
    window *is* the chart's — and the key under the chart names each server with
    the window it covers.  Spans that **no** server's log covers are shaded
     across the plot and keyed *no log*: when a run mixes logs of unrelated
     periods the window is mostly empty, and a flat stretch there must read as
     missing data, not as a quiet period (hovering the band names its span);
  - *Errors Over Time*: **failing** results only — informational codes (success,
    both Compare answers, a referral) are not plotted, so the curve is not
    inflated by operations that did what they were asked.  The curve is
    **stacked by result code**: the silhouette is the total, exactly where a
    single curve would be, and the colour underneath says which code built it —
    amber for what the client asked, violet for what the configuration refuses,
    red for what slapd failed to do, shaded by rank so two codes of one class
    stay distinguishable.  A refusal the log cannot attribute to either side
    (see the result-code classes) is a diagonal amber/violet **hatch** instead of
    a flat colour, and its legend swatch carries the same hatch.  A peak in one
    colour is one problem; a rise spread over several is a general one.  The
    legend under the chart names each band and its share, and hovering a slice
    lists the codes it is made of.  It carries the same per-server coverage
    lanes as *Simultaneous Connections*, since a fall at the edge of one
    server's file is exactly what this curve invites misreading as a recovery;
  - *Response Time Distribution*: how many operations fall into each etime
    bucket, each bar labelled with its exact count and share — the latency tail
    at a glance.  A cumulative share curve with its own 0-100 % axis used to run
    down the right-hand side; it was removed because the bars already carried
    every figure it derived from, and because on that axis each row past the
    second reads 100 %: the reader had to work out what the number referred to,
    for nothing.  The bars now have the width it and its label column took;
  - *Response Time Density*: the **shape** of that same distribution, on a
    logarithmic x axis whose window follows the data.  The eleven buckets above
    cannot show a shape that fits in one of them, and on a real 1 GiB access log
    99.9992 % of the operations finish under 1 ms; here the bins are equal in
    ratio (×1.58 per step) so the profile is readable — and this is also the
    only axis on which a latency distribution could ever look like a bell, which
    is what a log-normal latency is;
  - *Resource Consumers by Bind Account*: share of the cumulative operation
    time (etime) per bind DN, with each account's operation count and average
    time per operation;
  - *Operation Types*: share of SRCH / BIND / MOD / … ;
  - *Load by Server*: share of the operations each server of the analysed set
    handled, with each server's operation count in the legend — the only chart
    that only means something when several servers' logs are analysed together;
  - *Bind Usage*: share of each authentication method (simple / SASL /
    anonymous), with a footnote giving how many of the binds ran over TLS
    (ldaps or ldap + StartTLS) rather than in the clear;
  - *Result Code Breakdown*: every result code, successes included, as bars
    coloured by class, with the same codes drawn as **a pie** on the right — same
    order, same colours, sized by area.  One huge slice and a tail of slivers is
    what a result-code distribution looks like: on a concentrated log the first code
    alone is 63 % of everything and the top six are 99.99 %, so the chart says how
    few codes carry how much at a glance — no axis, no curve, no caption.  That
    right-hand side has been drawn four ways: a cumulative *curve* with its figures
    repeated in a text column beside it (the same number rendered twice, and the
    reader had to interpolate between 24 px rows to answer a question that is asked
    row by row), then a flat bar per row (which answered once the row was found),
    then those bars stacked so the sum could be seen being built (which needed a
    note to be read at all), and now the pie — which needs none.  Every code keeps
    **one colour** all through the report: the colour of its bar, of its slice here,
    and of its band in the stacked chart above.  A code of the dual class is the
    one exception, and it is deliberate: it is painted with the amber/violet
    **hatch** everywhere — bar, slice and band — so it reads as "either cause" at
    every place it appears, while its label and tooltip keep the violet base
    colour.  The left bars are on a log scale —
    counts span five orders of magnitude, and a linear scale would leave every code
    but the first invisible — so each bar carries its exact count and share, and
    **the scale itself is labelled under the bars** in decades: one step is ten
    times the one before.  Without that label the chart showed a percentage grid and
    nothing at all to measure a bar against;
  - *Failing Result Codes*: share of each failing result code, coloured by
    class — the dual class as the same amber/violet hatch as everywhere else.
    The informational results are not drawn as slices but counted and
    named in a note under the legend — on a 1 GiB production access log the
    Compare answers alone were 169 894 results, 32 % of the slices, which made
    the failure count read 48 % higher than it is.
  All are interactive — a tooltip follows the mouse and shows the exact value
  under the cursor.
- The OpenLDAP version, when the startup banner is present in the log.

### Tabbed HTML (`-o tabhtml`)

The same standalone HTML report, with its sections gathered into six tabs —
*Overview*, *Operations*, *Errors*, *Searches*, *Clients*, *Replication* —
instead of one long page.  The bar sits above the panels; a click selects a
tab, the arrow keys move between them, and `aria-selected` follows.

It is a **presentation** change only:

- every section stays in the DOM, so the page is still one self-contained file
  and `@media print` shows the whole report;
- `#sec-…` in the URL selects the tab that holds that section, and so does a
  link to any heading;
- the floating section index is hidden (the bar replaces it);
- without JavaScript every panel is simply visible, as with `-o html`.

`-o tab-html` is accepted as an alias.  None of this applies to `-o html`,
which is unchanged.

### JSON (`-o json`)

Complete machine-readable output via `nlohmann/json` with all aggregated data
structures (operation counts, error distribution, top operations, session
correlations, etc.).

`error_counts` is keyed by result code and carries the global message histogram
for that code, while `error_counts_by_app` repeats the same shape per
application (`who`) — each application's own counts and its own `text=`
messages.  The two agree: for a given code, the per-application figures add up
to the global ones.

### Replay (`-o replay`)

Pipe-delimited single-line format for jMeter/LoadRunner replay. Multi-line
operations (SRCH + SRCH_ATTR) are merged into a single line with results
included:

```
timestamp|conn|op|type|base|filter|attrs|scope|deref|binddn|authcid|authzid|err|etime|qtime|nentries|text
```

Every LDAP operation produces exactly one line, including those with no
RESULT line in the access log:

| Type | Notes |
|------|-------|
| `BIND` | `binddn` carries the DN; `err` is the expected result code. |
| `SRCH` | `base`, `filter`, `attrs`, `scope`, `deref`; `nentries` is the expected entry count. |
| `CMP` / `COMPARE` | `base` carries the entry DN. |
| `ADD`, `DEL`, `MOD`, `MODRDN` | write operations: `base` carries the target DN. |
| `EXT` | extended operation. |
| `ABANDON` | fire-and-forget cancellation; `filter` carries the numeric message id of the operation to abandon. |
| `UNBIND` | graceful disconnect. |

`ABANDON` and `UNBIND` have no RESULT line in the slapd access log, so their
replay rows carry no `err`/`etime`/`nentries`. They are still emitted (from
their own log line) so the replayer sees every operation.

The companion replayer (`jMeter_OpenLDAP_replay`) replays only `BIND`, `SRCH`,
`CMP`, `UNBIND` and `ABANDON`; the write operations (`ADD`, `DEL`, `MOD`,
`MODRDN`, `EXT`) are written here for traceability but skipped by the
replayer.

Use `--replay-separator` to change the delimiter:
```bash
slaplog -o replay --replay-separator tab access.log   # tab-separated
slaplog -o replay --replay-separator comma access.log # CSV format
```

Use `--replay-limit` to cap the number of operations written to the temp file:
```bash
slaplog -o replay --replay-limit 500000 access.log   # max 500K ops
slaplog -o replay --replay-limit 0 access.log         # unlimited
```

Replay data is written to a temporary file during processing, keeping memory
usage bounded regardless of log file size. Use `--replay-limit` as a safety
cap for extremely large log sets or limited disk space on `/tmp`.

This format is useful for replaying LDAP operations against a test server or
analyzing operation timing with external tools.

A complete jMeter run, with the options combined:
```bash
slaplog -o replay --replay-separator comma --output-date-format epoch \
  --replay-limit 500000 --log-format auto -q /var/log/slapd/access.log > jmeter_replay.csv
```

## Session Tracking

OpenLDAP supports the Session Tracking Request Control as defined in
draft-ietf-ldup-session-tracking. When enabled on the client side, slapd logs
the tracking information on each operation line:

```
conn=705807 op=1 [IP=10.67.10.49 NAME=vm3 USERNAME=uid=MyApplication,...] BIND dn="..." method=128
```

### How slaplog handles it

1. **Parsing**: After extracting `conn` and `op` via `RE_CONN_OP`, the parser
   checks if the remaining text starts with `[`. If so, it tries to match the
   session tracking block with two regexes:
   - Full: `[IP=... NAME=... USERNAME=...]`
   - Partial: `[IP=... NAME=...]` (no USERNAME)

2. **Storage**: The extracted fields (`session_ip`, `session_name`,
   `session_username`) are stored in the `Event` struct and forwarded to
   `ConnState` during aggregation.

3. **Correlation**: When session tracking data is encountered, a
   `SessionCorrelation` entry is created/updated. The key is
   `(restart_count, conn)` to handle slapd restarts where the connection ID
   counter resets.

4. **BIND DN enrichment**: When a BIND response is processed on the same
   connection, the correlation entry is updated with the DN used for
   authentication. The DN is extracted from the event data itself (not from
   `conn_state`) to avoid stale values across restart epochs.

### Restart handling

On `SLAPD_STARTING` events, an internal `restart_count` is incremented. All
subsequent session correlations use `(new_restart_count, conn)` as their key.
This prevents a connection ID from a previous server instance from colliding
with an ID from a new instance.

## Architecture

```
main.cpp
  ├── parse CLI arguments
  ├── collect_input_files() — discover log files
  ├── spawn a bounded worker pool (-j, capped at the file count)
  │     └── per file: process_file() → parse_line() → update_aggregator()
  │        into a local Aggregator, then merge_aggregators() under one mutex
  ├── progress bar thread (stderr)
  ├── write unknown lines if --unknown-lines
  └── print_report() — text / HTML / JSON / replay
```

### Two-stage parsing

Each log line goes through two distinct stages:

**Stage 1: `parse_line()`** → `Event`

- Detects the header format (RFC 3339 / OL26 / syslog / debug) via
  `try_parse_header()` — automatic per-line detection in `auto` mode — and
  converts the timestamp to RFC 3339 UTC via `convert_to_rfc3339_utc()`.
- Extracts `conn=`, `op=`, `fd=` identifiers.
- Strips `[IP=... NAME=... USERNAME=...]` session tracking blocks.
- Dispatches to the correct regex group based on the first character of the
  remaining text (`R` for RESULT, `B` for BIND, `S` for SRCH/SEARCH/SASL,
  etc.).
- Fills in the appropriate `Event` fields (kind, err, etime, dn, base,
  filter, session_ip, etc.).
- Returns `Event` — a value type that is cheap to copy between stages.

**Stage 2: `update_aggregator()`** → `Aggregator`

- Checks `ev.kind` and updates the corresponding counters.
- Maintains per-connection state (`ConnState`) and per-operation state
  (`OpState`).
- Tracks active connections, peak concurrent connections.
- Accumulates etime totals, averages, and top-N lists.
- Records errors, search bases, filters, attributes.
- Creates/updates session correlation entries.

### Parallelism

- No shared state between threads — each file gets its own `Aggregator`.
- Merging is a single-threaded post-processing step that unions all maps and
  keeps top-N entries.
- The progress bar runs on a dedicated thread and refreshes every 100 ms.
  Its total is the estimated **decompressed** size: a compressed file counts
  as its on-disk size times a measured expansion ratio (xz 17.7x, bzip2
  20.6x, gzip 13.3x), because the counter advances by decompressed bytes.

## File-by-File Guide

### `main.cpp`

Entry point. Defines CLI argument parsing, file collection (`wanted_log_file`,
`collect_input_files`), parallel processing orchestration, and report
dispatch. The `print_progress()` function renders a text progress bar on
stderr.

### `log_parser.hpp`

All data structures:

- **`Event`**: The output of `parse_line()`. Contains the parsed kind, raw
  text, optional LDAP fields, and session tracking fields.
- **`OpState`**: Mutable state for one LDAP operation within a connection.
  Tracks type, base, filter, attrs, scope, deref, who, etime, qtime,
  nentries, err, text, timestamp, etc.
- **`ConnState`**: Per-connection mutable state. Contains a map of ops,
  accumulated etime, binddn, authcid, src, session tracking fields.
- **`TopOpRow`** / **`TopConnRow`**: Rows for the top-N leaderboards.
  `TopOpRow` includes all fields needed for replay output.
- **`Stats`**: Simple scalar counters (lines, connections, unknowns).
- **`Aggregator`**: The main aggregation structure containing all maps,
  counters, and state. Includes `SessionCorrelation` and `server_events`.
  Also holds `restart_count` for correct session tracking across slapd
  restarts.
- **`LogFormat`** enum and helpers: `parse_log_format()`,
  `convert_to_rfc3339_utc()`, `try_parse_header()` with auto-detection support.

### `log_parser.cpp`

All parsing and aggregation logic:

- **Helpers**: `dequote`, `to_int`, `trim`, `normalize_filter`,
  `normalize_attrs`, `ts_sort_key`, `update_time_bounds`.
- **Format conversion**: `convert_to_rfc3339_utc()` with helpers
  `parse_debug_timestamp()`, `parse_syslog_timestamp()`, `format_rfc3339_utc()`.
  Converts any supported format to RFC3339 UTC.
- **`try_parse_header()`**: Multi-format header detection. In `AUTO` mode,
  tries all formats per line and reports the detected format via output
  parameter.
- **`parse_line()`**: ~450 lines of regex dispatch. Starts with header
  parsing, then connection/operation ID extraction, session tracking strip,
  and prefix-character-based dispatch to ~30 regex patterns.
- **`update_aggregator()`**: ~500 lines of counter and state updates. Routes
  on `ev.kind` to the correct handler (BIND, SRCH, RESULT, etc.).
- **`merge_aggregators()`**: Unions two `Aggregator` instances, keeping the
  top 100 for operations and connections.
- **File I/O**: `process_plain_file`, `process_gzip_file`, `process_bzip2_file`,
  `process_xz_file` — each reads lines and calls `parse_line` + `update_aggregator`.

### `regex_patterns.hpp`

All compiled patterns in the `slaplog_rx` namespace, backed by **PCRE2** (with
JIT in the native build) through the `std::regex`-like façade in
`pcre2_wrapper.hpp`. Organised into groups: headers, connection identifiers,
connection events, BIND patterns, operations, results, sub-patterns,
replication CSN, session tracking, and miscellaneous.

### `report.hpp` / `report.cpp`

Report generation:

- **`print_text_report()`**: ANSI-colored terminal output with section
  filtering via `has_section()`. Uses `print_table()` for formatted tables
  with automatic column-width calculation.
- **`print_html_report()`**: Standalone HTML with embedded CSS. Produces
  responsive, styled tables with colour gradients for etime values.
- **`print_json_report()`**: Machine-readable JSON output with all
  aggregated data, including session correlations.
- **`print_replay_report()`**: Pipe-delimited single-line output for
  jMeter/LoadRunner replay. Configurable delimiter via `--replay-separator`.
  Data written to a temp file during processing (bounded memory).

### `version.hpp`

Single source of truth for `SLAPLOG_VERSION` and `BUILD_NUMBER`.

### `embedded.hpp`

Holds the licence text and **this document**, printed by `-l` and `-D`.  It is
a **generated** file: `LICENSE` and `doc/slaplog.md` are the sources and
`make embedded` rewrites it — `make` does it automatically as soon as either
source changes, and `make check-doc` fails when it is stale.  Never edit it by
hand: the two copies used to be maintained that way and drifted apart.

### `utils.hpp`

Small utility functions: `ends_with` for filename suffix checks,
`parse_timestamp` for ISO 8601 parsing, and `format_time` for display
formatting.

## Extending the Parser

### Adding a new log line pattern

Patterns are **PCRE2** regular expressions (`slaplog_rx::Regex` is
`slaplog_pcre2::Regex`, a `std::regex`-like façade over PCRE2 — see
`pcre2_wrapper.hpp`; the native build JIT-compiles them). They are declared
**once at namespace scope**, never compiled inside `parse_line()`. Captures are
read through `slaplog_rx::MatchResults` / `MatchProxy`, *not* `std::smatch`:
`m[i]` converts implicitly to `std::string`/`std::string_view` and also offers
`.str()`, `.matched()` (did the group take part) and `.length()`.

1. Add the pattern to `regex_patterns.hpp` in the appropriate group:

   ```cpp
   inline const Regex RE_FOO(R"xx(^foo\s+(\S+)$)xx");
   ```

   A raw string (`R"xx(...)xx"`) keeps backslashes readable; pick a delimiter
   that does not occur in the pattern.
2. Match it in `parse_line()` (`log_parser.cpp`) and read the captures:

   ```cpp
   slaplog_rx::MatchResults m;
   if (slaplog_rx::regex_match(rest, m, RE_FOO)) {
       ev.kind = "FOO";        // a unique kind string
       ev.foo  = m[1].str();   // m[i] is a MatchProxy, not a std::ssub_match
   }
   ```

   Put the branch in the first-character dispatch when the line has one
   (`if (fc == 'F' && rest.compare(0, 3, "FOO") == 0)`), or in the catch-all
   section at the end when it does not.
3. In `update_aggregator()`, add an `if (ev.kind == "FOO")` handler.
4. Add any new field to `Event` and any counter to `Aggregator`, in
   `log_parser.hpp`.
5. Handle them in `merge_aggregators()` (and expose them in
   `print_json_report()` if the JSON must carry them).

### Adding a report section

1. Add the section data to `Aggregator` in `log_parser.hpp`.
2. Populate the data in `update_aggregator()`.
3. Add a `has_section("new_section")` block in `print_text_report()`.
4. Add the corresponding HTML table in `print_html_report()`.
5. Add the corresponding JSON key in `print_json_report()`.
6. Add the section name to the `-s` help text in `main.cpp`.

### Thread safety

- `parse_line()` holds no mutable global state: patterns are `const` and each
  match uses its own PCRE2 match block, so it is safe to call from several
  workers at once.
- `update_aggregator()` modifies its `Aggregator&` argument only.
- `merge_aggregators()` **is** called concurrently — each worker folds its
  finished file into the shared result under `merge_mtx`. It must therefore
  stay order-independent (compare sort keys, not raw text) and must not read
  shared state.
- Never use the non-reentrant libc time functions (`gmtime`, `localtime`,
  `asctime`): they return one process-wide static buffer, so two workers
  formatting a timestamp at the same time overwrite each other. Use
  `gmtime_r` / `localtime_r`.
- New mutable global state must be protected with `std::mutex`, or moved into
  the `Aggregator` struct.
)EMBED";

} // namespace embedded

#endif // EMBEDDED_HPP
