"""Search-query builder. Stdlib only. Zero network.

Doctrine: dork building produces precise, reviewable strings — shown before
run, never sprayed. This module generates the queries; the operator decides
whether and where to run them. Generating a string cannot touch a target.
"""
from core.base_module import BaseModule, ModuleResult


class DorkBuilderModule(BaseModule):
    @property
    def name(self) -> str:
        return "dork_builder"

    @property
    def alias(self) -> str:
        return "search like a native"

    @property
    def description(self) -> str:
        return "Builds precise, reviewable search queries from a domain or handle. No network."

    @property
    def reads(self) -> str:
        return "Nothing external. The target string you provide, plus built-in query templates."

    @property
    def returns(self) -> str:
        return "A set of labeled search queries (Google/Bing/GitHub-flavored), ready for review."

    @property
    def failure_modes(self) -> list:
        return [
            "This module makes no network requests — it cannot verify that any query returns results.",
            "Search engines personalize and regionalize; the same query returns different results per operator.",
            "Quoted-handle queries miss obfuscated variants (l33t, separators, display-name differences).",
        ]

    def run(self) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=self.target)
        t = self.target.strip().strip('"').strip("'")
        if not t:
            result.status = "FAILED"
            result.errors.append("give a domain or handle, e.g. runehall.com or @somehandle")
            return result
        is_domain = "." in t and " " not in t and not t.startswith("@")
        handle = t.lstrip("@")
        domain = t.lower()

        queries = []
        def q(label, text):
            queries.append({"label": label, "query": text})

        if is_domain:
            q("site mentions", '"%s"' % domain)
            q("subdomain chatter", '"%s" subdomain OR "subdomains of %s"' % (domain, domain))
            q("reviews & complaints", '"%s" (review OR scam OR complaint OR legit)' % domain)
            q("breach/credential chatter", '"%s" (breach OR leak OR "data breach")' % domain)
            q("social presence", '"%s" (instagram OR tiktok OR twitter OR telegram OR discord)' % domain)
            q("infrastructure", '"%s" (nameserver OR "IP address" OR ASN)' % domain)
            q("code & config leaks", '"%s" (github OR gitlab OR pastebin OR ".env")' % domain)
            q("news & announcements", '"%s" (launch OR update OR announcement OR maintenance)' % domain)
        else:
            q("exact handle", '"%s"' % handle)
            q("handle variants", '"%s" OR "%s" OR "%s"' % (
                handle, handle.replace("_", ""), handle.replace("_", ".")))
            q("handle + platform", '"%s" (site OR casino OR telegram OR discord)' % handle)
            q("handle + complaints", '"%s" (scam OR complaint OR review)' % handle)

        result.status = "SUCCESS"
        result.data = {"input": t, "input_type": "domain" if is_domain else "handle",
                       "query_count": len(queries), "queries": queries,
                       "note": "Review before running. Queries are strings, not actions."}
        result.add_finding(
            claim="%d reviewable search queries built for %s (no network touched)"
                  % (len(queries), t),
            tag="OBSERVED", method="template-based query generation (offline)",
            evidence={"query_count": len(queries)}, confidence="VERIFIED")
        return result
