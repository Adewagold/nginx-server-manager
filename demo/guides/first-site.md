# Your First Site - 5 Minute Tutorial

Welcome to your first website creation with Nginx Site Manager! This guide will walk you through creating your first static website in just 5 minutes.

## What You'll Learn

- How to create a static website
- Upload files using the drag-and-drop interface
- Configure basic settings
- View your live website

## Prerequisites

- Nginx Site Manager installed and running
- Web browser access to the management interface
- Basic HTML file (we'll create one if you don't have it)

## Step 1: Access the Dashboard

1. Open your web browser and navigate to the management interface:
   ```
   http://your-server-ip:8080
   ```

2. Log in with your admin credentials:
   - Username: `admin`
   - Password: Your configured admin password

3. You should see the main dashboard with:
   - Site overview cards
   - Quick action buttons
   - System status indicators

## Step 2: Create Your First Site

1. Click the **"Create New Site"** button on the dashboard

2. Fill out the basic site information:
   - **Site Name**: `my-first-site`
   - **Domain**: `my-first-site.local` (or your actual domain)
   - **Site Type**: Select **"Static Site"**
   - **Description**: `My very first website`

3. Click **"Next"** to proceed to configuration

## Step 3: Configure Site Settings

1. In the **Static Site Configuration** section:
   - **Web Root**: Leave as default (`/var/www/my-first-site`)
   - **Index File**: Leave as default (`index.html`)
   - **Error Pages**: Keep default settings

2. **Security Settings**:
   - Leave **"Enable security headers"** checked
   - Keep **"Hide server version"** checked

3. Click **"Create Site"** to generate the configuration

## Step 4: Upload Your Content

If you don't have an HTML file ready, let's create a simple one:

### Option A: Create a Simple HTML File

Create a file called `index.html` on your computer with this content:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>My First Site</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        .container {
            background: rgba(255, 255, 255, 0.1);
            padding: 40px;
            border-radius: 10px;
            text-align: center;
        }
        h1 {
            font-size: 3em;
            margin-bottom: 20px;
        }
        p {
            font-size: 1.2em;
            line-height: 1.6;
        }
        .success {
            background: #4CAF50;
            padding: 10px;
            border-radius: 5px;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🎉 Success!</h1>
        <div class="success">
            Your first website is now live!
        </div>
        <p>Welcome to your first website created with Nginx Site Manager.</p>
        <p>You can now upload more files, customize this page, or create additional sites.</p>
        <p><strong>Created:</strong> <span id="datetime"></span></p>
    </div>

    <script>
        document.getElementById('datetime').textContent = new Date().toLocaleString();
    </script>
</body>
</html>
```

### Option B: Upload Using File Manager

1. In your site's details page, click **"File Manager"**

2. You'll see the file upload interface with:
   - Drag-and-drop area
   - File browser
   - Upload progress indicators

3. **Upload your HTML file**:
   - Drag your `index.html` file to the upload area, OR
   - Click **"Choose Files"** and select your file
   - Wait for the upload progress to complete

4. You should see your file appear in the file list

## Step 5: Activate Your Site

1. Back in the site details page, click **"Enable Site"**

2. The system will:
   - Generate nginx configuration
   - Test the configuration
   - Reload nginx
   - Show confirmation message

3. Look for the green **"Site Active"** status indicator

## Step 6: View Your Live Website

1. In your site details, find the **"Site URL"** section

2. Click the link or copy the URL to your browser:
   ```
   http://my-first-site.local
   ```

3. You should see your website live!

## Congratulations! 🎉

You've successfully created your first website! Here's what you accomplished:

- ✅ Created a static site configuration
- ✅ Uploaded content using the file manager
- ✅ Generated and activated nginx configuration
- ✅ Viewed your live website

## What's Next?

Now that you have your first site running, you might want to:

1. **Add SSL Certificate**: Secure your site with HTTPS
   - Go to the **SSL** tab in your site settings
   - Click **"Request Certificate"** for automatic Let's Encrypt SSL

2. **Customize Your Domain**: 
   - Update DNS records to point to your server
   - Change the domain in site settings

3. **Upload More Content**:
   - Add CSS files, images, or JavaScript
   - Create additional pages
   - Build a complete website

4. **Try Advanced Features**:
   - Create a reverse proxy site
   - Set up load balancing
   - Configure custom error pages

## Troubleshooting

### Site Not Loading?

1. **Check site status**: Ensure the site shows "Active" in the dashboard
2. **Check domain**: Make sure you're using the correct URL
3. **Check logs**: View nginx logs in the System → Logs section
4. **Test nginx**: The system automatically tests configurations, but you can check manually

### File Upload Issues?

1. **File size**: Check if your files exceed the upload limit
2. **File type**: Ensure you're uploading allowed file types
3. **Permissions**: The system handles permissions automatically
4. **Space**: Check available disk space

### Domain Not Working?

1. **Local domain**: Add entries to your `/etc/hosts` file:
   ```
   127.0.0.1 my-first-site.local
   ```
2. **Real domain**: Update DNS A records to point to your server IP
3. **Firewall**: Ensure ports 80 and 443 are open

## Need Help?

- 📖 Check the [User Guide](../docs/user-guide.md) for detailed documentation
- 🔧 Visit [Troubleshooting Guide](../docs/troubleshooting.md) for common issues
- 💬 Join our community discussions for support

---

**Next Tutorial**: [SSL Setup Guide](ssl-setup.md) - Secure your site with HTTPS in one click!

*Estimated completion time: 5 minutes*