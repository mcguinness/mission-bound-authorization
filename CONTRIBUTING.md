# Contributing

This repository relates to activities in the Internet Engineering Task Force
([IETF](https://www.ietf.org/)). All material in this repository is considered
Contributions to the IETF Standards Process, as defined in the intellectual
property policies of IETF currently designated as
[BCP 78](https://www.rfc-editor.org/info/bcp78),
[BCP 79](https://www.rfc-editor.org/info/bcp79) and the
[IETF Trust Legal Provisions (TLP) Relating to IETF Documents](http://trustee.ietf.org/trust-legal-provisions.html).

Any edit, commit, pull request, issue, comment or other change made to this
repository constitutes Contributions to the IETF Standards Process
(https://www.ietf.org/).

You agree to comply with all applicable IETF policies and procedures, including,
BCP 78, 79, the TLP, and the TLP rules regarding code components (e.g. being
subject to a Simplified BSD License) in Contributions.

## How to Contribute

Contributions can be made by creating pull requests, opening an issue, or
posting to the working group mailing list. See above for the email address
and a note about policy.

Here are two ways to create a pull request ("PR"):

- Copy the repository and make a pull request using the Git command-line tool;
  see the [GitHub documentation](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/creating-a-pull-request) for more.

- You can use the GitHub UI as follows:
  - View the draft source
  - Select the pencil icon to edit the file (usually top-right on the screen)
  - Make edits
  - Select "Commit changes"
  - Add a title and explanatory text
  - Select "Propose"
  - When prompted, click on "Create Pull Request"

Document authors/editors are often happy to accept contributions of text,
and might be willing to help you through the process. Email them and ask.

## Reference Classification Convention

A draft in this repository lists a reference as normative when any
BCP 14 requirement, even one conditional on adopting an OPTIONAL
capability or companion profile, requires implementing or consulting
it. A conditional dependency stays normative and states its scope in
the text ("binds only a deployment that adopts X"); the core's Actor
Profile reference, confined to its OPTIONAL Delegation capability, is
the template.

Two bounds:

- **Maturity is a dependency boundary.** A Standards-Track draft never
  lists an Experimental draft as normative. A requirement that would
  create such a dependency moves into the Experimental draft, which
  places the duty on its own adopters; the Standards-Track draft keeps
  the reference informative and, where useful, points to it.
- **Named claims bind to properties, not documents.** Where a claim's
  condition can be stated as a deployment property (no unmediated
  path, isolated disclosure rendering), the profile states the
  property and cites the companion that defines the standard way to
  establish it; the citation may then stay informative.


## Working Group Information

Discussion of this work occurs on the [Web Authorization Protocol
Working Group mailing list](mailto:oauth@ietf.org)
([archive](https://mailarchive.ietf.org/arch/browse/oauth/),
[subscribe](https://www.ietf.org/mailman/listinfo/oauth)).
In addition to contributions in GitHub, you are encouraged to participate in
discussions there.

**Note**: Some working groups adopt a policy whereby substantive discussion of
technical issues needs to occur on the mailing list.

You might also like to familiarize yourself with other
[Working Group documents](https://datatracker.ietf.org/wg/oauth/documents/).
