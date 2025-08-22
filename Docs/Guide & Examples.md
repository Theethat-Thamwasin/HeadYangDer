# HeadYangDer - User Guide

This guide will help you install and use the **HeadYangDer** extension in Burp Suite, with examples and screenshots.

---

## 📥 Installation

1. Open **Burp Suite**.  
2. Go to **Extender → Extensions → Add**.  
3. Select the extension type:  
   - **Python** (using Jython 2.7)  
4. Load `HeadYangDer.py`  
5. The **HeadYangDer** tab will appear in Burp.  

!(./4.png)

---

## ⚡ Usage

### Step 1: Intercept a request
Capture traffic in **Proxy → HTTP history**, then send the request to **HeadYangDer**.  

![Intercept](./5.png)

---

### Step 2: Analyze Headers
The extension will check important security headers and display results:  
- ✅ Secure headers present  
- ❌ Missing headers  
- ⚠️ Weak/misconfigured headers  

![Header Analysis](./6.png)

---

### Step 3: View Results in the Extension Tab
Inside the **HeadYangDer** tab, you’ll see a clean table of results.  

![Results Tab](./7.png)

---

### Step 4: Export Findings
Click **Export** to save the results for use in penetration test reports.  

![Export](./8.png)

---

## 📚 Example Workflow

Here’s a full example showing the process from start to finish:  

1. Load the extension → ![Step 1](./9.png)  
2. Intercept a request → ![Step 2](./10.png)  
3. Analyze headers → ![Step 3](./11.png)  
4. Export report → ![Step 4](./12.png)  

---

## 🖼️ Additional Screenshots

For reference, more UI screenshots are included:  

![13](./13.png)  
![14](./14.png)  
![15](./15.png)  
![16](./16.png)  
![17](./17.png)  
![18](./18.png)  
![19](./19.png)  
![20](./20.png)  

---

## ✅ Summary

- Easy installation inside Burp Suite  
- Automatic detection of missing/weak headers  
- Exportable results for reporting  
- Lightweight & user-friendly interface  

---

