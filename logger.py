import logging
from logging.handlers import RotatingFileHandler

# Logger function
def setup_logger(app):
    if not app.debug:
        # Create a file handler for logging
        file_handler = RotatingFileHandler('error.log', maxBytes=10240, backupCount=10)
        file_handler.setLevel(logging.INFO)

        # Create a formatter and set it for the handler
        formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')
        file_handler.setFormatter(formatter)

        # Add the handler to the app's logger
        app.logger.addHandler(file_handler)

        # Set the logger level
        app.logger.setLevel(logging.INFO)
        app.logger.info('Application startup')
