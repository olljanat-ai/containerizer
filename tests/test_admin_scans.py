"""Bulk actions on Admin -> Repositories and Projects return to the list view they were sent from."""
from containerizer import admin_scans


def test_bulk_action_returns_to_its_view():
    form = {"view": ["show=all&scan=3&q=web+app&sort=commit&evil=x&project=Billing"]}
    assert admin_scans._view(form, "/admin/repositories") == \
        "/admin/repositories?show=all&scan=3&q=web+app&sort=commit&project=Billing"
    assert admin_scans._view({}, "/admin/repositories") == "/admin/repositories"
    assert admin_scans._view({"view": ["//evil.example/x"]}, "/admin/repositories") == "/admin/repositories"
    assert "value='show=hidden&amp;scan=3'" in admin_scans._view_field({"show": "hidden", "scan": 3})
