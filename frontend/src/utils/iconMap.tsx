import { 
  Mail, Globe, KeyRound, Gamepad2, CreditCard, Laptop,
  Server, Database, Cloud
} from 'lucide-react';
import { 
  FaGithub, FaInstagram, FaFacebook, FaXTwitter, FaDiscord,
  FaYoutube, FaLinkedin, FaFigma, FaTrello, FaSlack, FaAmazon, FaPaypal
} from 'react-icons/fa6';
import { SiNvidia, SiSnort } from 'react-icons/si';

export const getIconForVaultItem = (name: string, url?: string, size: number = 24) => {
  const n = (name || '').toLowerCase();
  const u = (url || '').toLowerCase();
  
  // Brand Icons (React-Icons / FontAwesome 6)
  if (n.includes('github') || u.includes('github')) return <FaGithub size={size - 2} />;
  if (n.includes('instagram') || u.includes('instagram')) return <FaInstagram size={size - 2} />;
  if (n.includes('facebook') || u.includes('facebook')) return <FaFacebook size={size - 2} />;
  if (n.includes('twitter') || n.includes('x.com') || n === 'x' || u.includes('twitter') || u.includes('x.com')) return <FaXTwitter size={size - 2} />;
  if (n.includes('discord') || u.includes('discord')) return <FaDiscord size={size - 2} />;
  if (n.includes('youtube') || u.includes('youtube')) return <FaYoutube size={size - 2} />;
  if (n.includes('linkedin') || u.includes('linkedin')) return <FaLinkedin size={size - 2} />;
  if (n.includes('figma') || u.includes('figma')) return <FaFigma size={size - 2} />;
  if (n.includes('trello') || u.includes('trello')) return <FaTrello size={size - 2} />;
  if (n.includes('slack') || u.includes('slack')) return <FaSlack size={size - 2} />;
  if (n.includes('amazon') || u.includes('amazon')) return <FaAmazon size={size - 2} />;
  if (n.includes('paypal') || u.includes('paypal')) return <FaPaypal size={size - 2} />;

  // Brand Icons 
  if (n.includes('teams') || u.includes('teams.microsoft')) return <Laptop size={size - 2} />;
  if (n.includes('overleaf') || u.includes('overleaf')) return <Globe size={size - 2} />;
  if (n.includes('nvidia') || u.includes('nvidia')) return <SiNvidia size={size - 2} />;
  if (n.includes('snort') || u.includes('snort')) return <SiSnort size={size - 2} />;

  // Category Icons (Lucide-React)
  if (n.includes('mail') || n.includes('gmail') || n.includes('yahoo') || n.includes('outlook')) return <Mail size={size} />;
  if (n.includes('bank') || n.includes('credit')) return <CreditCard size={size} />;
  if (n.includes('aws') || n.includes('cloud') || n.includes('azure') || n.includes('gcp')) return <Cloud size={size} />;
  if (n.includes('server') || n.includes('host') || n.includes('vps')) return <Server size={size} />;
  if (n.includes('database') || n.includes('sql') || n.includes('mongo')) return <Database size={size} />;
  if (n.includes('router') || n.includes('wifi') || n.includes('network')) return <Laptop size={size} />;
  
  // Fallbacks
  if (u) return <Globe size={size} />;
  
  return <KeyRound size={size} />;
};
