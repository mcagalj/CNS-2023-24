.PHONY: dev

dev:
	@echo "Starting dev-server"
	@uvicorn app.main:app --reload &
	@echo "Starting tailwindcss processor"
	@tailwindcss -i ./app/templates/styles.css -o ./app/static/styles.css -wp

dev-fastapi: 
	@echo "Starting dev-server"
	@uvicorn app.main:app --reload
