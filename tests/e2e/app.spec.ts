import { expect, test } from '@playwright/test'

test.describe('Vanity SOL GPU app', () => {
  test('renders and validates oversized target', async ({ page }) => {
    await page.goto('/')

    await expect(page.getByText('Vanity SOL GPU')).toBeVisible()

    await page.locator('#prefix').fill('A'.repeat(44))
    await page.locator('#suffix').fill('B')

    await expect(page.locator('#preview-addr')).toContainText('Prefix + suffix must be 44 chars or less')
    await expect(page.locator('#stat-eta')).toContainText('Invalid')
  })

  test('generates a vanity match and reveals the secret key', async ({ page }) => {
    await page.goto('/')

    await page.locator('#prefix').fill('')
    await page.locator('#suffix').fill('1')
    await page.locator('#btn-generate').click()

    await expect(page.locator('#btn-generate')).toContainText('Stop')
    await expect(page.locator('#subtitle')).toContainText('Running on CPU')

    await expect(page.locator('#result')).toHaveClass(/visible/, { timeout: 60_000 })
    await expect(page.locator('#subtitle')).toContainText('Match found')

    await page.locator('#btn-reveal').click()
    const revealed = await page.locator('#pk-text').textContent()

    expect(revealed).toBeTruthy()
    expect(revealed?.includes('•')).toBe(false)
    expect((revealed ?? '').length).toBeGreaterThan(80)
  })
})
