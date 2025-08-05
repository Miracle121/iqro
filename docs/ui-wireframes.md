# PAM System UI/UX Wireframes & Design Documentation

## 🎨 Design System Overview

### Design Tokens
- **Primary Colors**: Blue palette (#2563eb) for actions and highlights
- **Secondary Colors**: Gray palette for backgrounds and text
- **Status Colors**: Green (success), Red (danger), Yellow (warning), Blue (info)
- **Typography**: Inter for UI, JetBrains Mono for code/technical content
- **Spacing**: 4px base unit, consistent 8px, 16px, 24px, 32px scale
- **Border Radius**: 6px (small), 8px (medium), 12px (large), 16px (cards)
- **Shadows**: Soft, Medium, Strong levels for depth hierarchy

### Accessibility Standards
- **WCAG 2.1 AA** compliant
- **Color Contrast**: Minimum 4.5:1 for normal text, 3:1 for large text
- **Focus States**: Visible 2px blue outline for keyboard navigation
- **Screen Reader**: Proper ARIA labels and semantic HTML
- **Responsive**: Mobile-first design (320px+), Desktop optimized (1440px+)

---

## 📱 Screen Layouts & User Flows

### 1. **Login Page** 
**Route**: `/login`

#### Layout Description:
```
┌─────────────────────────────────────────────────────────────┐
│                    [PAM System Logo]                        │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                 LOGIN FORM                          │    │
│  │                                                     │    │
│  │  Username/Email: [__________________]               │    │
│  │  Password:       [__________________] [👁]          │    │
│  │                                                     │    │
│  │  [ ] Remember me     [Forgot Password?]            │    │
│  │                                                     │    │
│  │              [Sign In Button]                      │    │
│  │                                                     │    │
│  │  ─────────────── OR ───────────────                │    │
│  │                                                     │    │
│  │           [Continue with SSO]                      │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                             │
│              Need help? Contact Administrator               │
└─────────────────────────────────────────────────────────────┘
```

#### User Flow:
1. User enters credentials
2. System validates (rate limiting applies)
3. If MFA enabled → Show MFA modal overlay
4. Success → Redirect to dashboard based on role
5. Error → Show inline error messages with retry options

#### Components:
- **Input Fields**: Floating labels, validation states
- **Password Field**: Toggle visibility, strength indicator
- **Error States**: Red border, icon, descriptive message
- **Loading States**: Button spinner, form disable
- **MFA Modal**: TOTP input, backup code option, countdown timer

---

### 2. **MFA Verification Modal**
**Triggered**: During login if MFA enabled

#### Layout Description:
```
┌─────────────────────────────────────────────────────────────┐
│ [X]                 Multi-Factor Authentication             │
│                                                             │
│     [📱] Enter the 6-digit code from your authenticator    │
│                                                             │
│              [_] [_] [_] [_] [_] [_]                        │
│                                                             │
│               Time remaining: 00:28                        │
│                                                             │
│              [Verify Code Button]                          │
│                                                             │
│              ─── Having trouble? ───                       │
│                                                             │
│             [Use Backup Code Instead]                      │
│             [Resend Code]                                  │
│             [Contact Support]                              │
└─────────────────────────────────────────────────────────────┘
```

#### Features:
- **Auto-focus**: First input field
- **Auto-advance**: Move to next field on input
- **Countdown Timer**: Visual countdown with color changes
- **Backup Codes**: Alternative verification method
- **Accessibility**: Screen reader announcements for timer

---

### 3. **Admin Dashboard** 
**Route**: `/dashboard` (Admin Role)

#### Layout Description:
```
┌─────────────────────────────────────────────────────────────┐
│ [☰] PAM System    [🔍 Search]    [🔔] [👤 Profile] [⚙️]      │
├─────────────────────────────────────────────────────────────┤
│ [Sidebar Navigation]                                        │
│                                                             │
│ Dashboard          ┌─── Key Metrics Cards ───┐              │
│ Users              │ [Active Sessions: 23]    │              │
│ Sessions           │ [Pending Requests: 5]    │              │
│ Access Requests    │ [Security Alerts: 2]     │              │
│ Vault              │ [Users Online: 45]       │              │
│ Audit Logs         └─────────────────────────┘              │
│ System Targets                                              │
│ Compliance         ┌─── Session Activity Chart ───┐         │
│ Settings           │     [Line Chart - 24h View]   │         │
│                    │     Peak: 2:00 PM (35 users)  │         │
│                    └──────────────────────────────┘         │
│                                                             │
│                    ┌─── Recent Activities ───┐              │
│                    │ • John D. started SSH    │              │
│                    │   session to prod-web-01  │              │
│                    │ • Sarah L. requested      │              │
│                    │   access to database      │              │
│                    │ • Alert: Failed login     │              │
│                    │   attempts from IP...     │              │
│                    └─────────────────────────┘              │
└─────────────────────────────────────────────────────────────┘
```

#### Key Components:
- **Header**: Logo, global search, notifications, profile menu
- **Sidebar**: Collapsible navigation with role-based menu items
- **Metrics Cards**: Real-time counts with trend indicators
- **Charts**: Interactive session activity, user distribution
- **Activity Feed**: Live updates via WebSocket, filterable
- **Quick Actions**: Floating action button for common tasks

---

### 4. **User Dashboard**
**Route**: `/dashboard` (User/Vendor Role)

#### Layout Description:
```
┌─────────────────────────────────────────────────────────────┐
│ [☰] PAM System    [🔍 Search]    [🔔] [👤 Profile]          │
├─────────────────────────────────────────────────────────────┤
│ [Simplified Sidebar]                                        │
│                                                             │
│ Dashboard          ┌─── My Access Summary ───┐              │
│ Request Access     │ Active Sessions: 2       │              │
│ My Sessions        │ Pending Requests: 1      │              │
│ Vault              │ Available Systems: 12    │              │
│ Profile            └─────────────────────────┘              │
│                                                             │
│                    ┌─── Quick Access ───┐                   │
│                    │ [Request New Access] │                 │
│                    │ [Connect to System]  │                 │
│                    │ [View Vault Items]   │                 │
│                    └────────────────────┘                  │
│                                                             │
│                    ┌─── My Recent Sessions ───┐             │
│                    │ prod-web-01 • 2h 30m     │             │
│                    │ database-01 • Yesterday  │             │
│                    │ staging-api • 3 days ago │             │
│                    └─────────────────────────┘             │
└─────────────────────────────────────────────────────────────┘
```

#### Differences from Admin:
- **Simplified Navigation**: Only user-relevant sections
- **Personal Metrics**: Focus on user's own activities
- **Quick Actions**: Streamlined for common user tasks
- **Restricted Views**: No system-wide administration

---

### 5. **Access Request Flow**
**Route**: `/access/request`

#### Layout Description:
```
┌─────────────────────────────────────────────────────────────┐
│ [←] Request System Access                                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│ Step 1 of 3: Select Target System                          │
│ ████████████░░░░░░░░░░░░                                    │
│                                                             │
│ ┌─────────────────────────────────────────────────────┐     │
│ │ [🔍 Search systems...]                              │     │
│ └─────────────────────────────────────────────────────┘     │
│                                                             │
│ ┌─── Production Systems ───┐ ┌─── Development ───┐         │
│ │ [🟢] prod-web-01         │ │ [🟡] dev-api-01    │         │
│ │      Web Server          │ │      API Server    │         │
│ │      Last used: 2d ago   │ │      Last used: 1w │         │
│ └─────────────────────────┘ └───────────────────┘         │
│                                                             │
│ ┌─── Database Systems ───┐                                  │
│ │ [🔴] prod-db-01         │                                │
│ │      Critical System    │                                │
│ │      Requires approval  │                                │
│ └─────────────────────────┘                                │
│                                                             │
│                              [Continue →]                  │
└─────────────────────────────────────────────────────────────┘
```

#### Multi-Step Process:
1. **Step 1**: System selection with search and categorization
2. **Step 2**: Access details (duration, justification, emergency flag)
3. **Step 3**: Review and submit with approval workflow preview

#### Features:
- **System Cards**: Status indicators, metadata, access requirements
- **Search & Filter**: Real-time filtering, category tabs
- **Progress Indicator**: Step completion with ability to go back
- **Smart Suggestions**: Recently used systems, team recommendations

---

### 6. **Session Monitor**
**Route**: `/sessions/monitor`

#### Layout Description:
```
┌─────────────────────────────────────────────────────────────┐
│ [←] Active Sessions Monitor                [🔄] Auto-refresh │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│ ┌── Filters ──┐                           [📊] [📋] [📥]   │
│ │ User: All   │ ┌─── Live Session Grid ───┐               │
│ │ System: All │ │ User    System   Started Duration       │   │
│ │ Status: All │ │ john.d  web-01   14:32   2h 30m   [●]  │   │
│ └────────────┘ │ sarah.l db-01    13:15   3h 15m   [●]  │   │
│                │ mike.r  api-02   15:45   45m      [●]  │   │
│ [🔍 Search...] │ ...                                     │   │
│                └───────────────────────────────────────┘   │
│                                                             │
│ ┌─── Session Details Panel ───┐                            │
│ │ Selected: john.d @ web-01    │                           │
│ │                              │                           │
│ │ Started: Today 14:32         │                           │
│ │ Duration: 2h 30m             │                           │
│ │ Client IP: 192.168.1.50      │                           │
│ │ Session Type: SSH            │                           │
│ │                              │                           │
│ │ [📹 View Recording]          │                           │
│ │ [⏹️ Terminate Session]        │                           │
│ │ [📤 Send Message]            │                           │
│ └─────────────────────────────┘                           │
└─────────────────────────────────────────────────────────────┘
```

#### Real-time Features:
- **Live Updates**: WebSocket connection for real-time session data
- **Session Controls**: Terminate, message users, view recordings
- **Filtering**: Multi-criteria filtering with saved filter sets
- **Export Options**: CSV, PDF reports with custom date ranges
- **Session Recording**: Playback with seek controls and annotations

---

### 7. **Vault Interface**
**Route**: `/vault`

#### Layout Description:
```
┌─────────────────────────────────────────────────────────────┐
│ [←] Password Vault                        [➕ Add Entry]     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│ ┌── Categories ──┐                                          │
│ │ 📁 All (45)    │ ┌─── Vault Entries Grid ───┐           │
│ │ 🖥️ Servers (12) │ │ Name          System    Type    ... │ │
│ │ 🗄️ Databases(8)│ │ [🔒] Admin    web-01    SSH Key 🔄 │ │
│ │ 🌐 APIs (15)   │ │ [🔒] Root     db-01     Password   │ │
│ │ 🔧 Tools (10)  │ │ [🔒] API Key  payment   API Key    │ │
│ └───────────────┘ │ ...                                 │ │
│                   └───────────────────────────────────────┘ │
│ ┌── Tags ──┐                                                │
│ │ #prod     │      ┌─── Entry Details Panel ───┐           │
│ │ #critical │      │ 🔒 Admin @ web-01           │           │
│ │ #backup   │      │                             │           │
│ └──────────┘      │ SSH Private Key             │           │
│                   │ Created: 2 weeks ago        │           │
│                   │ Last used: Yesterday        │           │
│                   │ Auto-rotate: Enabled        │           │
│                   │                             │           │
│                   │ [📋 Copy] [👁 View]         │           │
│                   │ [✏️ Edit] [🗑️ Delete]        │           │
│                   └───────────────────────────────┘           │
└─────────────────────────────────────────────────────────────┘
```

#### Security Features:
- **Encryption**: Client-side encryption before API calls
- **Access Logging**: All vault operations logged and audited
- **Copy Protection**: Auto-clear clipboard after 30 seconds
- **Sharing**: Secure sharing with expiration and usage limits
- **Auto-rotation**: Scheduled password rotation with notifications

---

### 8. **Audit Logs**
**Route**: `/audit` (Admin/Auditor)

#### Layout Description:
```
┌─────────────────────────────────────────────────────────────┐
│ [←] Audit Logs                        [📊 Analytics] [📥]   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│ ┌── Advanced Filters ──┐                                    │
│ │ Date Range: [Last 7 days ▼]                              │
│ │ Event Type: [All ▼]                                      │
│ │ Severity:   [All ▼]                                      │
│ │ User:       [Search users...]                            │
│ │ IP Address: [Filter by IP...]                            │
│ │ [Apply Filters] [Reset] [Save Filter Set]               │
│ └─────────────────────────────────────────────────────────┘ │
│                                                             │
│ ┌─── Audit Trail ───┐                                       │
│ │ Timestamp    Event           User     IP          Severity │ │
│ │ 15:23:45    Login Success    john.d   192.168.1.50  ✅    │ │
│ │ 15:20:12    MFA Failed      sarah.l   10.0.0.25     ⚠️    │ │
│ │ 15:18:33    Vault Access    mike.r    192.168.1.75  ℹ️    │ │
│ │ 15:15:01    Session Start   anna.k    172.16.0.10   ℹ️    │ │
│ │ 15:12:44    Failed Login    unknown   203.0.113.1   ⚠️    │ │
│ └───────────────────────────────────────────────────────────┘ │
│                                                             │
│ ┌─── Event Details ───┐                                     │
│ │ Event ID: AUD-2023-001234                                │
│ │ Timestamp: 2023-08-15 15:23:45 UTC                      │
│ │ Event Type: Authentication                               │
│ │ Description: User login successful                       │
│ │ User: john.doe@company.com                              │
│ │ Source IP: 192.168.1.50                                 │
│ │ User Agent: Mozilla/5.0...                              │
│ │ Session ID: sess_abc123def456                           │
│ │ Additional Data: { "mfa_used": true, ... }              │
│ └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

#### Compliance Features:
- **Immutable Logs**: Tamper-evident with cryptographic hashing
- **Retention Policies**: Configurable retention with legal hold
- **Export Formats**: JSON, CSV, PDF with digital signatures
- **Real-time Alerts**: Anomaly detection with configurable rules
- **Compliance Reports**: SOX, HIPAA, PCI-DSS pre-built templates

---

### 9. **Profile & Settings**
**Route**: `/profile`

#### Layout Description:
```
┌─────────────────────────────────────────────────────────────┐
│ [←] Profile & Settings                                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│ ┌── Profile Info ──┐    ┌── Security Settings ──┐          │
│ │ [👤] John Doe    │    │ 🔐 Multi-Factor Auth    │          │
│ │     Admin        │    │    [✅ Enabled]         │          │
│ │                  │    │    [View Backup Codes]  │          │
│ │ john@company.com │    │                         │          │
│ │ IT Security Dept │    │ 🔑 Password            │          │
│ │ +1-555-0123     │    │    Last changed: 30d   │          │
│ │                  │    │    [Change Password]   │          │
│ │ [Edit Profile]   │    │                         │          │
│ └─────────────────┘    │ 🔒 Active Sessions     │          │
│                        │    2 active sessions    │          │
│ ┌── Preferences ──┐    │    [View All Sessions]  │          │
│ │ 🌙 Dark Mode     │    └─────────────────────────┘          │
│ │    [Toggle]      │                                        │
│ │                  │    ┌── API Access ──┐                 │
│ │ 🔔 Notifications │    │ Personal API Key        │         │
│ │    Email: ✅     │    │ [Generate New Key]      │         │
│ │    SMS: ❌       │    │                         │         │
│ │    Push: ✅      │    │ Rate Limit: 1000/hour  │         │
│ │                  │    │ Last used: 2 hours ago │         │
│ │ ⏰ Timezone     │    └─────────────────────────┘         │
│ │    UTC-05:00     │                                        │
│ └─────────────────┘                                        │
└─────────────────────────────────────────────────────────────┘
```

---

## 🎨 Component Library

### Design Components:

#### **Buttons**
- **Primary**: Blue background, white text, for main actions
- **Secondary**: Gray border, dark text, for secondary actions  
- **Danger**: Red background, white text, for destructive actions
- **Ghost**: Transparent, colored text, for subtle actions

#### **Form Controls**
- **Input Fields**: Rounded borders, floating labels, validation states
- **Select Dropdowns**: Custom styled with search capability
- **Checkboxes/Radio**: Custom designed with smooth animations
- **File Upload**: Drag & drop with progress indicators

#### **Navigation**
- **Sidebar**: Collapsible with icons and labels, role-based items
- **Breadcrumbs**: Clear hierarchy navigation
- **Tabs**: Underline style with smooth transitions
- **Pagination**: Previous/Next with page numbers

#### **Data Display**
- **Tables**: Sortable headers, row selection, inline actions
- **Cards**: Consistent padding, subtle shadows, hover states
- **Charts**: Recharts integration with consistent color palette
- **Metrics**: Large numbers with trend indicators

#### **Feedback**
- **Alerts**: Color-coded with icons (success, warning, error, info)
- **Toasts**: Non-intrusive notifications with auto-dismiss
- **Loading States**: Skeleton screens and progress indicators
- **Empty States**: Friendly illustrations with action prompts

#### **Overlays**
- **Modals**: Backdrop blur, escape key handling, focus trap
- **Dropdown Menus**: Smooth animations, keyboard navigation
- **Tooltips**: Contextual help with smart positioning
- **Popovers**: Rich content overlays for detailed information

---

## 📱 Responsive Design

### Breakpoints:
- **Mobile**: 320px - 767px (Single column, stacked layout)
- **Tablet**: 768px - 1023px (Adapted two-column, collapsible sidebar)
- **Desktop**: 1024px+ (Full layout with sidebar, multiple columns)

### Mobile Adaptations:
- **Navigation**: Bottom tab bar or hamburger menu
- **Tables**: Horizontal scroll or card-based layout
- **Forms**: Stacked fields, larger touch targets
- **Charts**: Simplified views with drill-down capability

### Touch Interactions:
- **Minimum Touch Targets**: 44px × 44px for better usability
- **Swipe Gestures**: Navigation between tabs, dismiss notifications
- **Pull to Refresh**: For real-time data screens
- **Long Press**: Context menus and shortcuts

---

## 🔒 Security UX Considerations

### Visual Security Indicators:
- **Connection Status**: Green padlock for secure connections
- **Session Timeout**: Countdown timer with warning notifications
- **Failed Attempts**: Progressive delays with visual feedback
- **Privilege Indicators**: Clear role badges and permission levels

### Error Handling:
- **Generic Error Messages**: No sensitive information exposure
- **Rate Limiting**: Clear messaging about retry timeouts
- **Session Expiry**: Graceful handling with re-authentication
- **Offline Handling**: Clear offline status with sync indicators

### Data Protection:
- **Auto-logout**: Configurable timeout with warning dialogs
- **Screen Lock**: Immediate lock on security events
- **Copy Protection**: Limited clipboard access with auto-clear
- **Print Restrictions**: Watermarks and permission controls

---

This comprehensive wireframe documentation provides the foundation for building a secure, accessible, and user-friendly PAM system interface that meets enterprise security requirements while maintaining excellent user experience.