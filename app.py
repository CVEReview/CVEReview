from flask import Flask, render_template, redirect, url_for, abort
import requests

app = Flask(__name__, static_url_path='', 
            static_folder='static',
            template_folder='templates')

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/CVE-<year>-<no>')
def cve(year, no):
    if (len(str(no)) >= 4 and len(str(year)) >= 4 ):
        return render_template('cve.html')
    else:
        return redirect(url_for('index'))

@app.route('/EPSS/CVE-<year>-<no>')
def epss(year, no):
    if (len(str(no)) >= 4 and len(str(year)) >= 4 ):    
        try:
            response = requests.get('https://api.first.org/data/v1/epss?cve=CVE-'+str(year)+'-'+str(no))
            print(response.request)
            if response.status_code == 200:
                return response.json()
            else:
                raise Exception('API returned an unsuccessful response')
        except Exception as e:
            print(e)
    abort(501)


    

# main driver function
if __name__ == '__main__':
    # run() method of Flask class runs the application
    # on the local development server.
    app.run(debug=False)
