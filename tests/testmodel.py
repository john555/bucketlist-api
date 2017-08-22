import unittest, datetime
from bucketlist import *
import json

db.drop_all()
db.create_all()

class TestUserModel(unittest.TestCase):

    def setUp(self):
        first_name = "John"
        last_name = 'Doe'
        username = 'jdoe'
        email = 'jdoe@example.com'
        password = 'theSecurePassword'
        
        user = User.query.filter_by(email = email).first()

        if user == None:
            user = User(first_name, last_name, username, email, password)

            db.session.add(user)
            db.session.commit()

            self.user = User.query.filter_by(email=user.email).first()
        else:
            self.user = user

        # Add a Bucket
        self.bucket_name = "Bucket 1"
        bucket_description = "Bucket 1's description"
        bucket = Bucket(self.bucket_name, bucket_description, owner = self.user)

        db.session.add(bucket)
        db.session.commit()

        self.bucket = Bucket.query.filter_by(user_id = self.user.id).first()
        # Add a BucketItem
        self.title = "To do 1"
        description="To do description"
        due_date = datetime.date(2017, 7, 25)
        item = BucketItem(self.title, description, due_date, bucket=self.bucket)

        db.session.add(item)
        db.session.commit()

        self.item = BucketItem.query.filter_by(bucket_id = self.bucket.id).first()

    # User

    def test_can_create_user(self):
        created_user = User.query.get(self.user.id)
        self.assertEqual(self.user.email, created_user.email)
    
    def test_can_verify_password(self):
        self.assertTrue(self.user.verify_password('theSecurePassword'))
    
    def test_can_change_password(self):
        # change pasword
        new_password = 'theNewPassword'
        self.user.set_password(new_password)
        db.session.commit()
        user = User.query.get(self.user.id)
        
        self.assertTrue(user.verify_password(new_password))
        self.assertFalse(user.verify_password('theSecurePassword'))

        # revert password
        self.user.set_password('theSecurePassword')
        db.session.commit()

    def test_can_check_if_email_exists(self):
        uname_exists1 = User.has_email('jdoe@example.com')
        self.assertTrue(uname_exists1)

        uname_exists2 = User.has_email('jbosco@example.com')
        self.assertFalse(uname_exists2)
    
    def test_can_check_if_username_exists(self):
        uname_exists1 = User.has_username('jdoe')
        self.assertTrue(uname_exists1)

        uname_exists2 = User.has_username('jbosco')
        self.assertFalse(uname_exists2)
    
    def test_can_check_by_user_id_if_user_exists(self):
        user_exists = User.user_exists(self.user.id)
        self.assertTrue(user_exists)

        user_exists = User.user_exists('3jdjd')
        self.assertFalse(user_exists)

    def test_can_delete_user(self):
        user = User.query.get(self.user.id)
        db.session.delete(user)
        db.session.commit()

        deleted_user = User.query.get(self.user.id)
        
        self.assertIsNone(deleted_user)

    def test_can_update_user(self):
        self.user.first_name = 'Benjamin'
        db.session.commit()

        modified_user = User.query.get(self.user.id)

        self.assertEqual('Benjamin', modified_user.first_name)

    # Bucket

    def test_can_add_bucket(self):
        self.assertEqual(self.bucket_name, self.bucket.name)

    def test_can_edit_bucket(self):
        name2 = "Some random name"
        description2 = "Some random description"
        bucket = Bucket.query.filter_by(user_id=self.user.id).first()
        bucket.name = name2
        bucket.description = description2

        db.session.commit()

        edited_bucket = Bucket.query.get(bucket.id)

        self.assertEqual(name2, edited_bucket.name)
        self.assertEqual(description2, edited_bucket.description)
    
    def test_can_delete_bucket(self):
        bucket_id = self.bucket.id

        db.session.delete(self.bucket)
        db.session.commit()

        bucket = Bucket.query.get(bucket_id)

        self.assertIsNone(bucket)
    
    # BucketItem

    def test_can_add_bucket_item(self):
        self.assertEqual(self.title, self.item.title)
    
    def test_can_edit_bucket_item(self):
        self.item.title = "Another title"

        db.session.commit()

        editted_item = BucketItem.query.get(self.item.id)
        self.assertEqual("Another title", editted_item.title)
    
    def test_can_delete_bucket_item(self):
        item_id = self.item.id

        db.session.delete(self.item)
        db.session.commit()

        item = BucketItem.query.get(item_id)

    # all

    def test_can_return_json(self):
        user_dict = dict()
        user_dict['first_name'] = self.user.first_name
        user_dict['last_name'] = self.user.last_name
        user_dict['user_name'] = self.user.username
        self.assertDictEqual(user_dict, self.user.dict())

        bucket_dict = dict()
        bucket_dict['id'] = self.bucket.id
        bucket_dict['name'] = self.bucket.name
        bucket_dict['description'] = self.bucket.description
        bucket_dict['created_at'] = self.bucket.created_at
        self.assertDictEqual(bucket_dict, self.bucket.dict())

        item_dict = dict()
        item_dict['id'] = self.item.id
        item_dict['title'] = self.item.title
        item_dict['description'] = self.item.description
        item_dict['is_complete'] = self.item.is_complete
        item_dict['due_date'] = self.item.due_date
        item_dict['created_at'] = self.item.created_at
        self.assertDictEqual(item_dict, self.item.dict())
