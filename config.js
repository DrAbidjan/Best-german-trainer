/* Public settings. Nothing secret belongs in this file.
   The anon key is MEANT to be public: it can only do what the database rules allow.
   NEVER paste a "service_role" key, a Lemon Squeezy API key or a webhook secret here. */
window.VT_CONFIG = {
  SUPABASE_URL: 'https://zovzhjagwwhwrbwibbtf.supabase.co',
  SUPABASE_ANON_KEY: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InpvdnpoamFnd3dod3Jid2liYnRmIiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTE3MjU3NzMsImV4cCI6MjEwNzMwMTc3M30.SBLoIKiSjr6FbJqtm4c96q5Icv0nC1UZrV5we5u29lM',
  SUPPORT_EMAIL: 'abid.26.am@gmail.com',
  PRICE_MONTHLY: '€5.99',
  PRICE_YEARLY: '€9.99',
  PREMIUM_VERB_COUNT: 534,
  PREMIUM_WORD_COUNT: 132,
  /* Sentence check: online check with the free LanguageTool service. Set to false to switch it off. */
  LT_ON: true,
  /* English text in the sentence check is translated into German with the free MyMemory service (about 5,000 characters per day per phone network). Set to false to switch it off. */
  MT_ON: true,
  /* AI sentence check (Premium). Keep false until the AI function is set up. Then change it to true. */
  AI_CORRECT: false
};
