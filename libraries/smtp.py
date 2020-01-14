import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

sender=  "MANUEL_A_BARRERA_MORA@homedepot.com"
receiver="MANUEL_A_BARRERA_MORA@homedepot.com"


msg = MIMEMultipart()
msg['To'] = sender
msg['From'] = receiver
msg['Subject'] = 'Viper Token Request'
body = MIMEText("Hey Cool thing")
msg.attach(body)
try:
	s = smtplib.SMTP()
	s.connect("mail2.homedepot.com")
	s.sendmail(sender, receiver, msg.as_string())
	print 'OK'
except Exception as e:
    print(e)
	
	
	
