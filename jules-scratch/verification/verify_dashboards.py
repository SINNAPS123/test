from playwright.sync_api import sync_playwright

def run():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto("http://127.0.0.1:5001/user_login")
        page.get_by_placeholder("Cod Unic sau Personal").click()
        page.get_by_placeholder("Cod Unic sau Personal").fill("CmdC1")
        page.get_by_role("button", name="Autentificare").click()
        page.screenshot(path="jules-scratch/verification/company_commander_dashboard.png")
        page.goto("http://127.0.0.1:5001/dashboard/battalion")
        page.screenshot(path="jules-scratch/verification/battalion_commander_dashboard.png")
        browser.close()

run()
