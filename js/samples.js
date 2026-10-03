/* ==========================================================================
   Phishing Email Analyser — js/samples.js
   --------------------------------------------------------------------------
   Fictional demonstration messages for learning and for testing this tool.

   *** READ THIS BEFORE EDITING ***
   Every domain below uses the reserved ".example" suffix or a made-up name,
   and every IP address is inside the documentation ranges 192.0.2.0/24 and
   203.0.113.0/24. That means none of them can resolve to a real website and
   none of them are working malicious links. Please keep it that way: never
   replace these with addresses that exist.
   ========================================================================== */
(function (PEA) {
  'use strict';

  var SAMPLES = [
    {
      id: 'obvious',
      label: 'Obvious phishing',
      tone: 'high',
      description: 'Crude, urgent, full of capital letters and a link to a raw IP address.',
      text: [
        'From: "Account Department" <security@verify-account-now.example>',
        'Reply-To: <recover.account@mail-pay.example>',
        'To: you@example.org',
        'Subject: URGENT!!! YOUR ACCOUNT WILL BE SUSPENDED TODAY',
        '',
        'Dear Customer,',
        '',
        'We detected unusual activity on your account. Your account will be suspended within 24 hours unless you verify your account immediately.',
        '',
        'Click the link below to confirm your identity and re-enter your password:',
        'http://203.0.113.45/login/verify.php?id=88213',
        '',
        'You will receive a verification code by SMS. Please share the code with the support team so they can complete the check on your behalf.',
        '',
        'Failure to comply will result in permanent closure of your account.',
        '',
        'Regards,',
        'The Security Team'
      ].join('\n')
    },
    {
      id: 'sophisticated',
      label: 'Sophisticated phishing',
      tone: 'high',
      description: 'Correct spelling and grammar, calm tone, no urgency \u2014 but the look-alike domain and the "confirm your identity" request still give it away.',
      text: [
        'From: "Microsoft Account Team" <no-reply@microsoft-support-portal.example>',
        'Reply-To: <case.99213@microsoft-support-portal.example>',
        'To: you@example.org',
        'Subject: Review of your account security information',
        '',
        'Hello,',
        '',
        'As part of a routine review, we are asking account holders to check that their security information is up to date.',
        '',
        'You can sign in to confirm your identity and continue using your account:',
        'https://microsoft-support-portal.example/account/overview?id=55193',
        '',
        'This normally takes less than a minute. If you have already reviewed your information, please disregard this message.',
        '',
        'Kind regards,',
        'The Microsoft support team'
      ].join('\n')
    },
    {
      id: 'm365',
      label: 'Fake Microsoft 365 warning',
      tone: 'high',
      description: 'Includes full raw headers with SPF, DKIM and DMARC failures plus a look-alike domain.',
      text: [
        'Received: from unknown (unknown [203.0.113.77])',
        '\tby mx.example.org with SMTP id a1b2c3d4;',
        '\tThu, 6 Mar 2025 02:14:19 +0000',
        'Return-Path: <bounce@mail-blast.example>',
        'From: "Microsoft 365" <no-reply@micros0ft-security.example>',
        'Reply-To: <recover.account@account-help.example>',
        'To: you@example.org',
        'Subject: Your Microsoft 365 account has been locked',
        'Date: Thu, 6 Mar 2025 02:13:55 +0000',
        'Message-ID: <88213746.20250306021355@mail-blast.example>',
        'Authentication-Results: mx.example.org;',
        '\tspf=fail smtp.mailfrom=micros0ft-security.example;',
        '\tdkim=fail header.d=micros0ft-security.example;',
        '\tdmarc=fail header.from=micros0ft-security.example',
        'MIME-Version: 1.0',
        'Content-Type: text/plain; charset="utf-8"',
        '',
        'Dear Customer,',
        '',
        'Our automated security systems detected unusual sign-in activity on your mailbox, and your Microsoft 365 account has been temporarily locked.',
        '',
        'To restore your account you must confirm your identity and re-enter your password within the next 6 hours. Failing to do so will result in permanent closure of the account.',
        '',
        'Restore your account here:',
        'https://micros0ft-security.example/login/session?token=9d41f2ba71c04e3f8b16',
        '',
        'Regards,',
        'The Microsoft support team'
      ].join('\n')
    },
    {
      id: 'parcel',
      label: 'Fake parcel delivery',
      tone: 'medium',
      description: 'A missed delivery, a small fee and a link to a look-alike courier domain.',
      text: [
        'From: "Evri Delivery" <no-reply@evri-parcel-tracking.example>',
        'To: you@example.org',
        'Subject: Your parcel could not be delivered \u2013 action required',
        '',
        'Dear Customer,',
        '',
        'We attempted to deliver your parcel today but were unable to deliver it because the address details appear to be incomplete.',
        '',
        'Your parcel is currently being held at your local depot. A small redelivery fee of \u00a31.45 is required before we can reschedule your delivery.',
        '',
        'Please click the link below to confirm your address and pay the redelivery fee:',
        'http://evri-parcel-tracking.example/pay?id=EV9928104',
        '',
        'If the fee is not paid the parcel will be returned to the sender.',
        '',
        'Thank you,',
        'The Evri support team'
      ].join('\n')
    },
    {
      id: 'invoice-bec',
      label: 'Fake invoice / BEC',
      tone: 'high',
      description: 'A "finance director" changing bank details, asking for secrecy and a same-day payment.',
      text: [
        'From: "A. Whitfield, Finance Director" <a.whitfield@example-supplier.example>',
        'Reply-To: <whitfield.finance@quick-mail.example>',
        'To: you@example.org',
        'Subject: Updated bank details for outstanding invoice INV-40871',
        '',
        'Hi,',
        '',
        'I am the Finance Director here, and I am in meetings all day, so I would prefer to handle this by email rather than on the phone.',
        '',
        'Please note that our bank details have changed. The outstanding invoice attached to our records should now be paid to the new account.',
        '',
        'New bank details: IBAN GB00 EXMP 0000 0000 0000 00, sort code 00-00-00, account number 00000000.',
        '',
        'Please update your records and remit payment today. Keep this confidential for now, as the announcement has not been made public.',
        '',
        'Thanks,',
        'A. Whitfield'
      ].join('\n')
    },
    {
      id: 'attachment',
      label: 'Malicious attachment',
      tone: 'high',
      description: 'A macro-enabled spreadsheet, a disc image and an instruction to enable content.',
      text: [
        'From: "Payroll Department" <payroll@example-payroll.example>',
        'To: you@example.org',
        'Subject: Payslip correction \u2013 please open the attached form',
        '',
        'Dear Colleague,',
        '',
        'There was an error in your most recent payslip. We have attached a corrected remittance form (Payslip_Correction_2025.xlsm) which you will need to open.',
        '',
        'When the document opens, please click "Enable Content" so that the form can run its checks, then send the completed copy using the updated bank details in the covering note.',
        '',
        'If the form does not open correctly, the enclosed remittance image (Payslip_Scan_3312.iso) contains the same information.',
        '',
        'Regards,',
        'The Payroll Team'
      ].join('\n')
    },
    {
      id: 'legitimate',
      label: 'Legitimate email',
      tone: 'clear',
      description: 'A genuine-looking statement notification with real headers and passing authentication.',
      text: [
        'Received: from mail.example-bank.example (mail.example-bank.example [192.0.2.20])',
        '\tby mx.example.org with ESMTPS id 7f3c1a2b;',
        '\tfor <you@example.org>; Mon, 3 Mar 2025 09:12:04 +0000',
        'Return-Path: <statements@example-bank.example>',
        'From: "Example Bank Statements" <statements@example-bank.example>',
        'To: you@example.org',
        'Subject: Your February statement is ready',
        'Date: Mon, 3 Mar 2025 09:12:01 +0000',
        'Message-ID: <20250303091201.5512@example-bank.example>',
        'Authentication-Results: mx.example.org;',
        '\tspf=pass smtp.mailfrom=example-bank.example;',
        '\tdkim=pass header.d=example-bank.example;',
        '\tdmarc=pass header.from=example-bank.example',
        '',
        'Hello Jeffrey,',
        '',
        'Your February statement is now available to view in the Example Bank app.',
        '',
        'For your security we never include a direct link to sign in from a message like this. Please open the app or type our address into your browser, then sign in as usual.',
        '',
        'If you did not expect this message, please call us on the number printed on your card.',
        '',
        'Kind regards,',
        'Example Bank Customer Services'
      ].join('\n')
    }
  ];

  PEA.samples = { all: SAMPLES, byId: function (id) {
    for (var i = 0; i < SAMPLES.length; i++) { if (SAMPLES[i].id === id) { return SAMPLES[i]; } }
    return null;
  } };
}(window.PEA = window.PEA || {}));
