# Administrator Dashboard

Een eenvoudig administrator dashboard voor gebruikersbeheer met email verificatie.

## Functionaliteiten

- Gebruikers aanmaken, wijzigen en verwijderen
- Rollen beheren
- Email verificatie met 2-minuten timeout
- EmailJS integratie voor het versturen van verificatiecodes

## Gebruik

Open `index.html` in je browser.

## EmailJS Configuratie

Om emails te versturen, configureer EmailJS in `index.html`:
```javascript
const EMAILJS_CONFIG = {
  publicKey: 'YOUR_PUBLIC_KEY',
  serviceId: 'YOUR_SERVICE_ID',
  templateId: 'YOUR_TEMPLATE_ID'
};
```

## Installatie

1. Clone de repository
2. Open `index.html` in een browser
3. Configureer EmailJS naar wens
