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

![5](./5.png)

![6](./6.png)

![7](./7.png)

---

## ⚡ Usage

### Step 1: Send a Request to HeadYangDer
From the **Proxy tab** or the **Request/Response view**, right-click and choose:  
`Extensions → HeadYangDer → Send to Header Checker`  

![8](./8.png)  

---

### Step 2: Analyze Headers
Inside the **HeadYangDer** tab you will see the header analysis table.  
By default, all **6 security headers** are selected.  

![9](./9.png)  

You can also choose only some headers (e.g., 3 out of 6):  

![10](./10.png)  

---

### Step 3: Edit and Interact with Results
- **Edit a cell**: Double-click to modify the value.  
  ![11](./11.png)  

- **Highlight a row**: Click once to highlight a request.  
  ![12](./12.png)  

- **Clear Selection**: Use the **Clear Selection** button to remove highlighting.  
  ![13](./13.png)  

---

### Step 4: Adjust the View
- **Zoom In**  
  ![14](./14.png)  

- **Zoom Out**  
  ![15](./15.png)  

- **Reset Layout**: Use the **Set Default View** button.  
  ![16](./16.png)  

---

### Step 5: Export Results
You can export the table to **PNG** for reporting.  

- Export with **all 6 headers selected**:  
  ![17](./17.png)  
  ![18](./18.png)  

- Export with **only 4 headers selected**:  
  ![19](./19.png)  
  ![20](./20.png)  

---

## ✅ That's it Simple and Look Clean (maybe TT)

HeadYangDer steps up and makes it simple to check missing or weak HTTP security headers during penetration testing.
- Export results for reporting  

