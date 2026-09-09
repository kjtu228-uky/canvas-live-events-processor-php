**Canvas PHP Live Events Processor**

This script is a JWT-Secured webhook receiver (RSA / RS256 via JWKS) and event processor. It validates the event, responds to Canvas as quickly as possible, then checks for a configured event handler.

An event can have multiple handlers configured. This allows handlers to be kept simple and focused.
