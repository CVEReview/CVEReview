from flask import Flask, render_template, redirect, url_for, abort, jsonify
import requests
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from dbModels import db, cve


app = Flask(__name__, static_url_path='', 
            static_folder='static',
            template_folder='templates')
 
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql:///cvereview_db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
 
db.init_app(app)
migrate = Migrate(app, db)


@app.route('/')
def index():
    
    

    return render_template('index.html')


@app.route('/CVE-<year>-<no>')
def cveView(year, no):
    if (len(str(no)) >= 4 and len(str(year)) >= 4 ):

        cveNumber = "CVE-"+str(year)+"-"+str(no)

        cveData = cve.query.filter_by(cveId=cveNumber).first()
        print(cveData.data)
        return render_template('cve.html')
    else:
        return redirect(url_for('index'))

@app.route('/api/CVE-<year>-<no>')
def cveApi(year, no):
    if (len(str(no)) >= 4 and len(str(year)) >= 4 ):

        cveNumber = "CVE-"+str(year)+"-"+str(no)

        cveData = cve.query.filter_by(cveId=cveNumber).first()
       
        return jsonify(cveData.data)

    abort(501)

@app.route('/api/EPSS/CVE-<year>-<no>')
def epssApi(year, no):
    if (len(str(no)) >= 4 and len(str(year)) >= 4 ):    
        cveNumber = "CVE-"+str(year)+"-"+str(no)

        cveData = cve.query.filter_by(cveId=cveNumber).first()
        
        return jsonify({"cve":cveNumber, "epss":cveData.epss})
        #try:
        #    response = requests.get('https://api.first.org/data/v1/epss?cve=CVE-'+str(year)+'-'+str(no))
        #    print(response.request)
        #    if response.status_code == 200:
        #        return response.json()
        #    else:
        #        raise Exception('API returned an unsuccessful response')
        #except Exception as e:
        #    print(e)
    abort(501)


    

# main driver function
if __name__ == '__main__':
    # run() method of Flask class runs the application
    # on the local development server.
    app.run(debug=False)
