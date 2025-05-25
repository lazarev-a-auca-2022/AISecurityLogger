# Latest Report Link Troubleshooting

If the "Latest Report" button on the reports page is not working, this may be due to an issue with the symlink or file path. The system tries to maintain a symbolic link named `latest_report.html` that points to the most recent security report.

## Automatic Fix

The application includes tools to automatically fix this issue:

1. Run the update script to fix the symlink:
   ```bash
   ./update_latest_report.sh
   ```

2. Check if the link is working properly:
   ```bash
   ./check_latest_report.sh
   ```

## Manual Fix

If you need to manually fix the issue:

1. Find the most recent security report in the `/reports` directory.
2. Delete the existing `latest_report.html` file if it exists:
   ```bash
   rm reports/latest_report.html
   ```
3. Create a new symlink pointing to the most recent report:
   ```bash
   cd reports
   ln -s security_report_YYYYMMDD_HHMMSS.html latest_report.html
   ```
   Replace `YYYYMMDD_HHMMSS` with the timestamp of the most recent report.

## How it Works

When the application generates a new security report, it should automatically:
1. Create the report file with a timestamp in the name
2. Create or update the `latest_report.html` symlink to point to the newest report
3. The web UI also has JavaScript that will directly link to the newest report as a fallback

If running in Docker, note that the paths inside the container (`/app/reports/`) are different from the paths on the host system (`/home/main/AISecurityLogger/reports/`). This can sometimes cause issues with symlinks.
