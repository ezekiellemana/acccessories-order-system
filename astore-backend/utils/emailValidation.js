// utils/emailValidation.js
export const isLikelyFakeEmail = (email) => {
  const fakeDomains = [
    'example.com', 'test.com', 'fake.com', 'invalid.com',
    'nonexistent.com', 'temp.com', 'demo.com', 'sample.com',
    'mailinator.com', '10minutemail.com', 'guerrillamail.com',
    'throwawaymail.com', 'disposable.com'
  ];
  
  const domain = email.split('@')[1]?.toLowerCase();
  return fakeDomains.includes(domain);
};

export const isCommonProvider = (email) => {
  const commonProviders = [
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
    'aol.com', 'icloud.com', 'protonmail.com', 'zoho.com',
    'mail.com', 'yandex.com'
  ];
  
  const domain = email.split('@')[1]?.toLowerCase();
  return commonProviders.includes(domain);
};