from project import create_app
import os

app = create_app()

# We now handle session initialization in project/__init__.py within the before_request function

if __name__ == '__main__':
    if 'DYNO' in os.environ:
        # Running on Heroku, use gunicorn
        port = int(os.environ.get('PORT', '5000'))
        app.run(host='0.0.0.0', port=port)
    else:
        # Running locally
        app.run(host='localhost', port=2000, debug=True)