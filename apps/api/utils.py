# import os
# from sendgrid import SendGridAPIClient
# from sendgrid.helpers.mail import Mail
# from django.contrib.auth.models import User

# msg = Mail(
#     from_email='ionganea77@gmail.com',
#     to_emails=User.email,
#     subject='Sending with Twilio SendGrid is Fun',
#     html_content='<strong>and easy to do anywhere, even with Python</strong>')
# try:
#     sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
#     sg.set_sendgrid_data_residency("eu")
#     # uncomment the above line if you are sending mail using a regional EU subuser
#     response = sg.send(msg)
#     print(response.status_code)
#     print(response.body)
#     print(response.headers)
# except Exception as e:
#     print(e.message)
