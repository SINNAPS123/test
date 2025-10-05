import re
from playwright.sync_api import Page, expect

def test_verifications(page: Page):
    # 1. Login
    page.goto("http://localhost:5001/user_login")
    page.get_by_placeholder("Cod de autentificare").fill("test_gradat_code")
    page.get_by_role("button", name="Autentificare").click()
    expect(page).to_have_url("http://localhost:5001/dashboard")

    # 2. Verify Weekend Leave Export Page
    page.goto("http://localhost:5001/gradat/weekend_leaves")
    expect(page.get_by_role("heading", name="Listă Învoiri Weekend (Vineri-Duminică)")).to_be_visible()
    # We can't test the download directly in this script, but we can verify the button exists.
    expect(page.get_by_role("link", name="Exportă (Word)")).to_be_visible()
    page.screenshot(path="jules-scratch/verification/weekend_leaves_page.png")

    # 3. Verify Internal Permissions Ranking Page
    page.goto("http://localhost:5001/gradat/permissions/ranking")
    expect(page.get_by_role("heading", name="Clasament Permisii (Intern)")).to_be_visible()
    page.screenshot(path="jules-scratch/verification/internal_permissions_ranking.png")

    # 4. Verify Public Permissions Ranking Page
    # First, generate a public link
    page.goto("http://localhost:5001/permissions/links")
    page.get_by_role("button", name="Generează").click()

    # Reload the links to get the new one
    page.get_by_role("button", name="Reîncarcă").click()

    # Get the URL of the first public link
    public_url = page.locator("#linksTbody a").first.get_attribute("href")

    # Log out to simulate a public user
    page.goto("http://localhost:5001/logout")

    # Navigate to the public URL
    page.goto(public_url)
    expect(page.get_by_role("heading", name="Clasament Permisii")).to_be_visible()
    page.screenshot(path="jules-scratch/verification/public_permissions_ranking.png")