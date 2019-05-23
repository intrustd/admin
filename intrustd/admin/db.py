from sqlalchemy import Column, String, DateTime, ForeignKey, \
    Integer, UniqueConstraint, func, create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

from contextlib import contextmanager
from datetime import datetime
import json

Base = declarative_base()

def datetime_json(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S")

def parse_json_datetime(dt):
    try:
        return datetime.strptime(dt, "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None

class Task(Base):
    __tablename__ = 'task'

    id = Column(String, primary_key=True)
    alias = Column(String, nullable=True)

    created_on = Column(DateTime, default=func.now())
    run_after = Column(DateTime, default=func.now())
    started_on = Column(DateTime, nullable=True)
    finished_on = Column(DateTime, nullable=True)
    retain_until = Column(DateTime)

    application = Column(String)
    persona = Column(String(64), nullable=True)

    command = Column(String)
    data = Column(String, default="")
    result = Column(String, nullable=True)

    __table_args__ = ( UniqueConstraint('application', 'alias', 'persona', name='alias_uc'), )

    def to_json(self):
        instance = { 'domain': self.application }
        if self.persona is not None:
            instance['persona'] = self.persona

        r = { 'id': self.id,
              'created': datetime_json(self.created_on),
              'run_after': datetime_json(self.run_after),
              'retain_until': datetime_json(self.retain_until),

              'app': instance,

              'command': self.command,
              'data': json.loads(self.data) }

        if self.started_on is not None:
            r['started'] = datetime_json(self.started_on)

        if self.finished_on is not None:
            r['finished'] = datetime_json(self.finished_on)

            if self.result is not None:
                r['result'] = json.loads(self.result)

        return r

class Version(Base):
    __tablename__ = 'version'

    version = Column(Integer, primary_key=True)

engine = create_engine('sqlite:///intrustd/admin.db')
Session = sessionmaker(bind=engine)

def do_migrate():
    latest_version = 1

    session = Session()
    connection = engine.connect()

    try:
        if not engine.dialect.has_table(engine, 'version'):
            connection.execute('CREATE TABLE version(version integer primary key)')

        res = list(session.query(Version).order_by(Version.version.desc()).limit(1))

        version = 0
        if len(res) > 0:
            version = res[0].version

        if version <= 0:
            connection.execute('''
              CREATE TABLE task(id VARCHAR NOT NULL PRIMARY KEY,
                                alias VARCHAR,
                                created_on TIMESTAMP NOT NULL,
                                run_after TIMESTAMP NOT NULL,
                                started_on TIMESTAMP,
                                finished_on TIMESTAMP,
                                retain_until TIMESTAMP NOT NULL,
                                application VARCHAR NOT NULL,
                                persona CHAR(64),
                                command VARCHAR NOT NULL,
                                data VARCHAR NOT NULL,
                                result VARCHAR)
            ''')
            connection.execute('''
              CREATE UNIQUE INDEX alias_uc ON task(application, alias, persona);
            ''')

        if version < latest_version:
            session.add(Version(version=latest_version))
        session.commit()

    finally:
        session.close()
        connection.close()

do_migrate()

@contextmanager
def session_scope():
    session = Session()

    try:
        yield session
        session.commit()
    except:
        session.rollback()
        raise
    finally:
        session.close()
