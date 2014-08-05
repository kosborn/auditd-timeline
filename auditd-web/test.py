import os
from sqlite3 import dbapi2 as sqlite3
from flask import Flask, request, session, g, redirect, url_for, abort, \
     render_template, flash, _app_ctx_stack



from flask import Flask
app = Flask(__name__)


app.config['DATABASE'] = '../audit.db'

def get_db():
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    top = _app_ctx_stack.top
    if not hasattr(top, 'sqlite_db'):
        top.sqlite_db = sqlite3.connect(app.config['DATABASE'])
    return top.sqlite_db


@app.teardown_appcontext
def close_db_connection(exception):
    """Closes the database again at the end of the request."""
    top = _app_ctx_stack.top
    if hasattr(top, 'sqlite_db'):
        top.sqlite_db.close()

@app.route("/")
def hello():
    page = '<h1>Select a query to run against the database.<h1>'
    for sql in os.listdir('../sql-examples'):
        page = page+'<a href=/sql?f='+sql+'>'+sql+'</a><br/>'
    return page

@app.route("/sql")
def runQuery():
    query = open('../sql-examples/'+request.args.get('f'),'r').read()
    curs = get_db().cursor()
    try:
        values = curs.execute(query)
    except Exception as e:
        return "ERROR: %s" % e
    logData = values.fetchall()
    table = '<style>table, th, td {border: 1px solid black;} td{padding:1px} table{ border-collapse: collapse;}</style><table>'
    for row in logData:
        table += '<tr>'
        for column in row:
            table += "<td>%s</td>" % column
        table += "</tr>"
    table += "</table>"
    return table

if __name__ == "__main__":
    app.run()

