OMNIVENDOR UPDATED SETUP

1. Copy these files into your existing project folder, keeping the public folder structure.
2. Create/edit .env in the project root using .env.example as a template:
   PORT=3000
   ADMIN_EMAIL=your-admin-email
   ADMIN_PASSWORD=your-admin-password
   TOKEN_SECRET=a-long-random-secret
3. Install packages:
   npm install
4. Start:
   npm start
5. Open:
   Admin: http://localhost:3000/admin-login.html
   Vendor: http://localhost:3000/vendor.html

Vendor accounts can self-register from the Vendor Portal login page. No email verification is used.
Accounts are stored in data.json. New account passwords are plain text as requested for this local demo.
Keep this project local and do not use real/reused passwords. Do not deploy with plain-text passwords.
The old ADMIN_KEY is no longer used for browser sync; admin requests use the admin login session token.
Existing bcrypt-hashed accounts remain supported by the login route if bcryptjs is installed, but new registrations store a plain password.
