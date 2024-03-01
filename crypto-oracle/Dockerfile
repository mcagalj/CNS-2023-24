FROM python:3.12-bullseye

ENV APP_DIR=app
ENV WORKDIR=code

WORKDIR /${WORKDIR}
COPY ./requirements.txt /$WORKDIR/requirements.txt
RUN pip install --no-cache-dir --upgrade -r /${WORKDIR}/requirements.txt

COPY /${APP_DIR} /$WORKDIR/${APP_DIR}

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "80"]
