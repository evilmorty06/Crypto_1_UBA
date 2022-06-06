FROM tiangolo/uwsgi-nginx-flask:python3.7

ADD --chown=root:root ./app /app

COPY ./requirements.txt /tmp/requirements.txt

RUN pip install -r /tmp/requirements.txt

ENV FLAG FLAG{dummy_flag}

WORKDIR /app
