from app import db, Activity
from app import app

with app.app_context():
    activities = [
        Activity(name='Amazing race', location='Adv Zone', price=600, timeslots='2025-10-25T09:00:00,2025-10-25T12:00:00', slots=29, expiration_days=7),
        Activity(name='Zipline', location='Adv Zone', price=608, timeslots='2025-10-25T12:30:00,2025-10-25T14:30:00', slots=6, expiration_days=7),
        Activity(name='Absailing', location='Adv Zone', price=608, timeslots='2025-10-25T12:30:00,2025-10-25T15:30:00', slots=6, expiration_days=7),
        Activity(name='Horse Riding', location='Horse Rid Adv', price=350, timeslots='2025-10-25T12:30:00,2025-10-25T14:00:00', slots=5, expiration_days=7),
        Activity(name='Quad bike', location='Horse Rid Adv', price=550, timeslots='2025-10-25T12:30:00,2025-10-25T14:00:00', slots=5, expiration_days=7),
        Activity(name='Smash that', location='Smash that', price=370, timeslots='2025-10-25T12:30:00,2025-10-25T14:00:00', slots=4, expiration_days=7),
        Activity(name='Game drive', location='Adv Zone', price=280, timeslots='2025-10-25T12:30:00,2025-10-25T14:00:00', slots=3, expiration_days=7),
        Activity(name='paintball game', location='Horse Rid Adv', price=230, timeslots='2025-10-25T14:00:00,2025-10-25T15:30:00', slots=10, expiration_days=7),
        Activity(name='Indy Go Cart', location='Horse Rid Adv', price=300, timeslots='2025-10-25T14:00:00,2025-10-25T15:30:00', slots=4, expiration_days=7),
        Activity(name='Djembe dromme', location='Adv Zone', price=224, timeslots='2025-10-25T14:00:00,2025-10-25T15:30:00', slots=3, expiration_days=7),
    ]
    for act in activities:
        db.session.add(act)
    db.session.commit()