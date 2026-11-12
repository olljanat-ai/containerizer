# Developers and ownership

Mapping hundreds of Git repositories to products and business units by hand is slow, and the repositories rarely say
who owns them. The people who commit to them usually do. **Admin → Developers** (administrators) lists everyone who
committed to the organizations' repositories in the last six months, and uses the business units you give them to
suggest where the repositories and products nobody mapped belong.

## Where the list comes from

At the end of every [organization scan](scheduled-scans.md) run, full or **Discover**, the worker reads the commit
authors of the last six months from the provider's API (Azure DevOps, GitLab, GitHub), for every repository of the
scan with a commit in that time. Nothing extra is cloned. It keeps:

- one developer per e-mail address (lower case), with the name of their latest commit;
- the repositories each developer committed to, the number of their commits there in the six months, and their
  latest commit there. That date only moves forward; someone whose commits are older than six months stays listed
  with 0 commits.

A repository is read again when it has a newer commit than the last time, or once a week (the counts age), so most
runs ask the API about few repositories. Repositories that are disabled (themselves or their project), archived or
empty are left out. Automation is left out as it is read (`[bot]` accounts, `noreply` addresses, build
services without an e-mail address); tick **Ignore** for any other service account. Why reading a repository failed
is in `OrgRepository.HistoryError`.

## Map developers to business units

![Admin → Developers: developers with their business units, suggestions and repositories](images/admin-developers.png#only-light)
![Admin → Developers: developers with their business units, suggestions and repositories](images/admin-developers-dark.png#only-dark)

Pick each developer's **Business unit** and press **Save changes** (once, for every row you changed). **Suggested**
is the business unit of the products of the repositories they commit to, weighed by commits: it says *matches* when
it is the one set, *differs* when it is another. **Apply suggestions** sets it for every developer without a
business unit whose suggestion is at least 60% sure. Filter by **No business unit** or **Ignored**, or search by
name, e-mail, repository or business unit.

So start from what is mapped already: map a few products to business units, apply the developers' suggestions,
check them, then turn to the repositories.

## Suggestions for what nobody mapped

![Admin → Developers → Suggestions: products and repositories without a business unit, with the suggested one](images/admin-developers-suggestions.png#only-light)
![Admin → Developers → Suggestions: products and repositories without a business unit, with the suggested one](images/admin-developers-suggestions-dark.png#only-dark)

**Suggestions** weighs the business units of each repository's developers (not ignored) by their commits:

- **Products without a business unit**, such as the ones made from projects (below): **Set** the suggested one, or
  **Apply suggestions** for all that are at least 60% sure.
- **Repositories without a business unit**: their applications have no product, a product without a business unit,
  or the repository was not assessed at all (no application code, say). Map their applications on
  **Admin → Applications** to a product of the suggested business unit.

## One product per project

![Admin → Developers → Projects → products](images/admin-developers-projects.png#only-light)
![Admin → Developers → Projects → products](images/admin-developers-projects-dark.png#only-dark)

As a starting point, an Azure DevOps project (a GitLab subgroup) is one product. After every run the worker:

1. makes a product named after each project that has an assessed application and that nobody decided on yet (an
   existing product of that name is used instead);
2. maps the applications of the project's repositories that nobody mapped to it. Each application is mapped
   automatically once only: if someone changes its mapping, that stays.

On **Projects → products** change a project's product, or choose **No product** (a project with several products:
map its applications yourself) or **Automatic**. The applications that were mapped automatically follow the
project's product; the ones people mapped stay. **Map now** runs the step at once. Disabled projects are left
alone, and GitHub organizations have no projects. The change history records every change the scan or people make
(**Via: scan** for the automatic ones).

## In the database

| Table | What |
| --- | --- |
| `Developer` | one row per e-mail address: `BusinessUnitId`, `Ignored` and `Note` are set by people |
| `DeveloperRepository` | developer × repository: `Commits` (six months), `LastCommitAt` |
| `OrgRepository.HistoryAt`, `HistoryCommitAt`, `HistoryError` | when its authors were read, its newest commit then, why it failed |
| `OrgProject.ProductId`, `ProductMappedAt` | the project's product; `ProductMappedAt` NULL: not decided (automatic) |
| `Application.ProductAutoAt` | when the application was mapped to its project's product automatically |

The procedure `AutoMapProjects` does the mapping; the scan worker's login (`<schema>_writer`) may run it, and may
not change products or mappings otherwise.
