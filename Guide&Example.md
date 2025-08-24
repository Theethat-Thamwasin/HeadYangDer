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

![4](./Docs/4.png)

![5](./Docs/5.png)

![6](./Docs/6.png)

![7](./Docs/7.png)

---

## ⚡ Usage

### Step 1: Send a Request to HeadYangDer
From the **Proxy tab** or the **Request/Response view**, right-click and choose:  
`Extensions → HeadYangDer → Send to Header Checker`  

![8](./Docs/8.png)  

---

### Step 2: Analyze Headers
Inside the **HeadYangDer** tab you will see the header analysis table.  
By default, all **6 security headers** are selected.  

![9](./Docs/9.png)  

You can also choose only some headers (e.g., 3 out of 6):  

![10](./Docs/10.png)  

---

### Step 3: Edit and Interact with Results
- **Edit a cell**: Double-click to modify the value.  
  ![11](./Docs/11.png)  

- **Highlight a row**: Click once to highlight a request. (for old Version)
  ![12](./Docs/12.png)  

- **Clear Selection**: Use the **Clear Selection** button to remove highlighting. (for old Version)  
  ![13](./Docs/13.png)  

---

### Step 4: Adjust the View
- **Zoom In**  
  ![14](./Docs/14.png)  

- **Zoom Out**  
  ![15](./Docs/15.png)  

- **Reset Layout**: Use the **Set Default View** button.  
  ![16](./Docs/16.png)  

---

### Step 5: Export Results
You can export the table to **PNG** for reporting.  

- Export with **all 6 headers selected**:  
  ![17](./Docs/17.png)  
  ![18](./Docs/18.png)  

- Export with **only 4 headers selected**:  
  ![19](./Docs/19.png)  
  ![20](./Docs/20.png)  

---

### Step 6: History of Results
You can views past scan and result that can be load and export later.  

- View and Load Past results:  
  ![21](./Docs/21.png)  
  ![22](./Docs/22.png)  

- You can Delete unwanted history result:  
  ![23](./Docs/23.png)  

---

## ✅ That's it, Simple and Looks Clean 

HeadYangDer steps up and makes it simple to check missing or weak HTTP security headers during penetration testing.

