import smtplib


def send_recovery_email(sender, receiver, unique_recovery_link):
    message = """From: MCShop <""" + sender + """">
    To: User <""" + receiver + """>\n
    Subject: Password recovery
    \n
    Looks like you lost your password!\n
    Reset your password by clicking in this link:\n
    """ + unique_recovery_link + """\n
    
    It wasn't you? Ignore that message.\n
    Good luck using our site ~MCShop\n
    """

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login('your email', 'your password')
        server.sendmail(sender, receiver, message)
        print("Successfully sent email")
    except smtplib.SMTPException:
        print("Error: unable to send email")

    return message
