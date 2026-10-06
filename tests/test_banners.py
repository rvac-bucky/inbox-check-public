import pytest
from app.core import strip_external_banners as strip

BODY = 'From: Payroll <payroll@examp1e-hr.test>\nSubject: Update your direct deposit\n\nConfirm your bank details today.'

BANNERS = [
    'CAUTION: This email is NOT from Verisma or Verisma Safe Senders',
    'CAUTION: This email originated from outside of the organization. Do not click links or open attachments unless you recognize the sender and know the content is safe.',
    'WARNING: This e-mail originated from outside the rvacyber.com domain. Do not click on links or open attachments until validating their authenticity.',
    "You don't often get email from payroll@examp1e-hr.test. Learn why this is important",
    'This message came from outside your organization. [EXTERNAL] notice',
    'ATTENTION: This email was sent from outside the company.',
    'External Sender: be cautious of links and attachments. This email came from outside the organization.',
]


@pytest.mark.parametrize('banner', BANNERS)
def test_banner_removed_and_body_kept(banner):
    out = strip(banner + '\n' + BODY + '\n' + banner)
    assert banner not in out and 'Confirm your bank details today.' in out and 'payroll@examp1e-hr.test' in out


def test_external_subject_tag_removed():
    assert 'Subject: Update your direct deposit' in strip('Subject: [EXTERNAL] Update your direct deposit')


def test_fake_banner_carrying_a_link_is_kept():
    fake = 'CAUTION: This email originated from outside the organization. Verify at http://login-verify.test/now'
    assert 'http://login-verify.test/now' in strip(fake + '\n' + BODY)


def test_ordinary_lines_mentioning_caution_are_kept():
    text = 'Please use caution when lifting boxes.\nExternal auditors arrive Monday.\n' + BODY
    assert strip(text) == text
