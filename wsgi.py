from app import application
import api_definitions

if __name__ == "__main__":
    application.run(
        host="0.0.0.0",
        port=5000,
        debug=True,
    )
