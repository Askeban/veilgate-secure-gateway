# Veilgate Landing Page — Setup Guide

## 1. Store Registrations in Google Sheets (Free)

### Step 1: Create a Google Sheet
1. Go to [Google Sheets](https://sheets.google.com) and create a new spreadsheet
2. Name it **"Veilgate Interest Registrations"**
3. In Row 1, add these headers:
   | A | B | C | D | E | F | G | H |
   |---|---|---|---|---|---|---|---|
   | Timestamp | Name | Email | Company | Job Title | Team Size | Use Case | Message |

### Step 2: Add the Apps Script
1. In your Google Sheet, go to **Extensions → Apps Script**
2. Delete any existing code and paste the following:

```javascript
function doPost(e) {
  var lock = LockService.getScriptLock();
  lock.tryLock(10000);

  try {
    var sheet = SpreadsheetApp.getActiveSpreadsheet().getActiveSheet();
    var data = JSON.parse(e.postData.contents);

    sheet.appendRow([
      new Date().toISOString(),
      data.name || "",
      data.email || "",
      data.company || "",
      data.title || "",
      data.team_size || "",
      data.use_case || "",
      data.message || ""
    ]);

    return ContentService
      .createTextOutput(JSON.stringify({ status: "ok" }))
      .setMimeType(ContentService.MimeType.JSON);
  } catch (err) {
    return ContentService
      .createTextOutput(JSON.stringify({ status: "error", message: err.toString() }))
      .setMimeType(ContentService.MimeType.JSON);
  } finally {
    lock.releaseLock();
  }
}
```

3. Click **Save** (💾)
4. Click **Deploy → New Deployment**
5. Select type: **Web app**
6. Set:
   - **Execute as:** Me
   - **Who has access:** Anyone
7. Click **Deploy**
8. **Copy the Web App URL** — it looks like:
   `https://script.google.com/macros/s/AKfycbx.../exec`

### Step 3: Connect to Your Website
Open `index.html` and find this line near the bottom:
```javascript
const FORM_ENDPOINT = "";
```
Paste your URL:
```javascript
const FORM_ENDPOINT = "https://script.google.com/macros/s/YOUR_SCRIPT_ID/exec";
```

That's it! Every form submission will now appear as a new row in your Google Sheet.

---

## 2. Deploy to Vercel (Free)

### Option A: Quick Deploy via CLI
```bash
# Install Vercel CLI (one-time)
npm i -g vercel

# From the website directory
cd website
vercel

# Follow the prompts:
# - Link to your account
# - Project name: veilgate
# - Framework: Other
# - Build command: (leave empty, press Enter)
# - Output directory: ./ 
```

### Option B: Deploy via GitHub
1. Push your `website/` folder to a GitHub repo
2. Go to [vercel.com](https://vercel.com) and sign in with GitHub
3. Click **"Import Project"** → select your repo
4. Set **Root Directory** to `website`
5. Click **Deploy**

### Custom Domain (Optional)
After deployment, in Vercel Dashboard:
1. Go to your project → **Settings → Domains**
2. Add your custom domain (e.g., `veilgate.io` or `shyld.dev`)
3. Follow the DNS instructions Vercel provides

---

## 3. Testing the Flow
1. Open your deployed site
2. Fill out the interest form
3. Check your Google Sheet — a new row should appear within seconds!
