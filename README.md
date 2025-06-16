Signed Mouse Driver Usage
=================

Overview
---
This is a signed mouse driver used in popular paid Valorant aimbots. We reversed it and bypassed all of its authentication.

It was originally posted a few months ago, but the authentication was hardcoded (Windows build number, computer name, etc.). Through reversing, we figured out and automated the entire authentication, no more hardcoded values.

How to Use It
---
It's very simple to use. The provided minimal usage handles everything for you, except loading the driver. You just need to load the driver and run it, and it should work out of the box. However note that this driver may not work on some versions of Windows 11.

How to load the driver
---
  #### 1. Open Command Prompt as Admin 
  Type cmd in the Windows Start menu, right-click on it, and select Run as admin.

  #### 2. Create the Driver Service
  Run the following command:

```cmd
sc create salesto type=kernel binPath="C:\Path\To\Driver.sys"
```

#### 3. Start the Driver
And lastly, run this command to load the driver:

```cmd
sc start salesto
```
