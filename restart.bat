
            @echo off
            timeout /t 2 /nobreak
            taskkill /F /PID 15428
            set PRODUCTION=true
            start "" "python" "app.py"
            