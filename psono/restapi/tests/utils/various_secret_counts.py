import random
import string
from django.test import TestCase

from restapi.models import (
    User, Data_Store, Share, Secret, Secret_Link, Share_Tree, Group, 
    User_Share_Right, Group_Share_Right, User_Group_Membership
)
from restapi.utils import encrypt_with_db_secret
from restapi.utils import get_secret_counts_for_users
from restapi.utils import create_share_link
import uuid


class SecretCountsUtilsTest(TestCase):
    """
    Test the get_secret_counts_for_users utility function
    """

    def setUp(self):
        """Set up test data"""
        
        # Create test users
        self.user1 = User.objects.create(
            email=encrypt_with_db_secret("test1@example.com"),
            email_bcrypt="bcrypt_hash_1",
            username="test1@psono.pw",
            authkey="authkey1",
            public_key="5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c649",
            private_key="abddebec9d20cecf7d1cab95ad6c6394db3826856bf21c2c6af9954e9816c2239f5df697e52",
            private_key_nonce=''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(48)),
            secret_key="77cde8ff6a5bbead93588fdcd0d6346bb57224b55a49c0f8a22a807bf6414e4d82ff60711422",
            secret_key_nonce=''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(48)),
            user_sauce='4c36bb1c6a33a5f3159afc2af6f6cda5391e85120ab5b7a7b18c0c9b7ef66c3d',
            is_email_active=True
        )
        
        self.user2 = User.objects.create(
            email=encrypt_with_db_secret("test2@example.com"),
            email_bcrypt="bcrypt_hash_2",
            username="test2@psono.pw",
            authkey="authkey2",
            public_key="5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c649",
            private_key="abddebec9d20cecf7d1cab95ad6c6394db3826856bf21c2c6af9954e9816c2239f5df697e52",
            private_key_nonce=''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(48)),
            secret_key="77cde8ff6a5bbead93588fdcd0d6346bb57224b55a49c0f8a22a807bf6414e4d82ff60711422",
            secret_key_nonce=''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(48)),
            user_sauce='7a3323247ce6de08b4631f2e5e87df1ed39a203610718101ece8a524f30211d4',
            is_email_active=True
        )
        
        self.user3 = User.objects.create(
            email=encrypt_with_db_secret("test3@example.com"),
            email_bcrypt="bcrypt_hash_3",
            username="test3@psono.pw",
            authkey="authkey3",
            public_key="5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c649",
            private_key="abddebec9d20cecf7d1cab95ad6c6394db3826856bf21c2c6af9954e9816c2239f5df697e52",
            private_key_nonce=''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(48)),
            secret_key="77cde8ff6a5bbead93588fdcd0d6346bb57224b55a49c0f8a22a807bf6414e4d82ff60711422",
            secret_key_nonce=''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(48)),
            user_sauce='2658403bcbbac0bb6dfe617b20a23d1fa9d2e8e074d06d6859481e4689fc6471',
            is_email_active=True
        )
        
        # Create datastores for users
        self.user1_datastore = Data_Store.objects.create(
            user_id=self.user1.id,
            type="password",
            description="User 1 datastore",
            data=b"encrypted_data",
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            secret_key=''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            secret_key_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        )
        
        self.user2_datastore = Data_Store.objects.create(
            user_id=self.user2.id,
            type="password",
            description="User 2 datastore",
            data=b"encrypted_data",
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
            secret_key=''.join(random.choice(string.ascii_lowercase) for _ in range(256)),
            secret_key_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        )
        
        # Create shares
        self.share1 = Share.objects.create(
            user_id=self.user1.id,
            data=b"encrypted_share_data",
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        )
        
        self.share2 = Share.objects.create(
            user_id=self.user2.id,
            data=b"encrypted_share_data",
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        )
        
        self.share3 = Share.objects.create(
            user_id=self.user1.id,
            data=b"encrypted_share_data",
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        )
        
        # Create secrets
        self.secret1 = Secret.objects.create(
            user_id=self.user1.id,
            data=b"secret_data_1",
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        )
        
        self.secret2 = Secret.objects.create(
            user_id=self.user1.id,
            data=b"secret_data_2",
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        )
        
        self.secret3 = Secret.objects.create(
            user_id=self.user2.id,
            data=b"secret_data_3",
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        )
        
        self.secret4 = Secret.objects.create(
            user_id=self.user2.id,
            data=b"secret_data_4",
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        )
        
        self.secret5 = Secret.objects.create(
            user_id=self.user1.id,
            data=b"secret_data_5",
            data_nonce=''.join(random.choice(string.ascii_lowercase) for _ in range(64)),
        )

    def test_secrets_in_user_datastores_only(self):
        """Test counting secrets that exist only in user datastores"""
        
        # Link secrets to datastores
        Secret_Link.objects.create(
            secret_id=self.secret1.id,
            link_id=uuid.uuid4(),
            parent_datastore_id=self.user1_datastore.id
        )
        
        Secret_Link.objects.create(
            secret_id=self.secret2.id,
            link_id=uuid.uuid4(),
            parent_datastore_id=self.user1_datastore.id
        )
        
        Secret_Link.objects.create(
            secret_id=self.secret3.id,
            link_id=uuid.uuid4(),
            parent_datastore_id=self.user2_datastore.id
        )
        
        # Test the function
        user_ids = [str(self.user1.id), str(self.user2.id), str(self.user3.id)]
        result = get_secret_counts_for_users(user_ids)
        
        # Assert results
        self.assertEqual(result[str(self.user1.id)], 2, "User 1 should have 2 secrets from datastore")
        self.assertEqual(result[str(self.user2.id)], 1, "User 2 should have 1 secret from datastore")  
        self.assertEqual(result[str(self.user3.id)], 0, "User 3 should have 0 secrets")

    def test_secrets_in_directly_accessible_shares(self):
        """Test counting secrets in shares that users have direct access to"""
        
        # Create share trees (root level shares)
        Share_Tree.objects.create(
            share_id=self.share1.id,
            path="share1rootid",
            parent_datastore_id=self.user1_datastore.id
        )
        
        Share_Tree.objects.create(
            share_id=self.share2.id,
            path="share2rootid",
            parent_datastore_id=self.user2_datastore.id
        )
        
        # Create share rights for user3 to access share1 and share2
        User_Share_Right.objects.create(
            user_id=self.user3.id,
            share_id=self.share1.id,
            read=True,
            write=False,
            grant=False,
            accepted=True
        )
        
        User_Share_Right.objects.create(
            user_id=self.user3.id,
            share_id=self.share2.id,
            read=True,
            write=True,
            grant=False,
            accepted=True
        )
        
        # Link secrets to shares
        Secret_Link.objects.create(
            secret_id=self.secret1.id,
            link_id=uuid.uuid4(),
            parent_share_id=self.share1.id
        )
        
        Secret_Link.objects.create(
            secret_id=self.secret2.id,
            link_id=uuid.uuid4(),
            parent_share_id=self.share1.id
        )
        
        Secret_Link.objects.create(
            secret_id=self.secret3.id,
            link_id=uuid.uuid4(),
            parent_share_id=self.share2.id
        )
        
        # Test the function
        user_ids = [str(self.user1.id), str(self.user2.id), str(self.user3.id)]
        result = get_secret_counts_for_users(user_ids)
        
        # Assert results - user3 should have access to all 3 secrets through direct share rights
        self.assertEqual(result[str(self.user1.id)], 0, "User 1 should have 0 secrets (no rights to shares)")
        self.assertEqual(result[str(self.user2.id)], 0, "User 2 should have 0 secrets (no rights to shares)")
        self.assertEqual(result[str(self.user3.id)], 3, "User 3 should have 3 secrets from direct share access")

    def test_secrets_in_nested_shares(self):
        """Test counting secrets in nested shares through Share_Tree hierarchy"""
        
        # Create share tree hierarchy: share1 -> share3 (share3 is nested under share1)
        Share_Tree.objects.create(
            share_id=self.share1.id,
            path="rootshare1",
            parent_datastore_id=self.user1_datastore.id
        )
        
        # Create nested share using create_share_link utility
        link_id = uuid.uuid4()
        create_share_link(
            link_id=link_id,
            share_id=self.share3.id,
            parent_share_id=self.share1.id,
            parent_datastore_id=None
        )
        
        # Give user2 access to the root share (share1)
        User_Share_Right.objects.create(
            user_id=self.user2.id,
            share_id=self.share1.id,
            read=True,
            write=False,
            grant=False,
            accepted=True
        )
        
        # Put secrets in the nested share (share3)
        Secret_Link.objects.create(
            secret_id=self.secret1.id,
            link_id=uuid.uuid4(),
            parent_share_id=self.share3.id
        )
        
        Secret_Link.objects.create(
            secret_id=self.secret2.id,
            link_id=uuid.uuid4(),
            parent_share_id=self.share3.id
        )
        
        # Test the function
        user_ids = [str(self.user1.id), str(self.user2.id)]
        result = get_secret_counts_for_users(user_ids)
        
        # User2 should have access to secrets in the nested share through inherited rights
        self.assertEqual(result[str(self.user1.id)], 0, "User 1 should have 0 secrets")
        self.assertEqual(result[str(self.user2.id)], 2, "User 2 should have 2 secrets from nested share")

    def test_secrets_through_group_membership(self):
        """Test counting secrets accessible through group membership"""
        
        # Create a group
        group = Group.objects.create(
            name="Test Group",
            public_key="5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c649"
        )
        
        # Add user3 to the group
        User_Group_Membership.objects.create(
            user_id=self.user3.id,
            group_id=group.id,
            accepted=True
        )
        
        # Create share tree
        Share_Tree.objects.create(
            share_id=self.share1.id,
            path="groupshare",
            parent_datastore_id=self.user1_datastore.id
        )
        
        # Give group access to share1
        Group_Share_Right.objects.create(
            group_id=group.id,
            share_id=self.share1.id,
            read=True,
            write=False,
            grant=False
        )
        
        # Link secrets to the share
        Secret_Link.objects.create(
            secret_id=self.secret1.id,
            link_id=uuid.uuid4(),
            parent_share_id=self.share1.id
        )
        
        Secret_Link.objects.create(
            secret_id=self.secret2.id,
            link_id=uuid.uuid4(),
            parent_share_id=self.share1.id
        )
        
        # Test the function
        user_ids = [str(self.user1.id), str(self.user2.id), str(self.user3.id)]
        result = get_secret_counts_for_users(user_ids)
        
        # User3 should have access through group membership
        self.assertEqual(result[str(self.user1.id)], 0, "User 1 should have 0 secrets")
        self.assertEqual(result[str(self.user2.id)], 0, "User 2 should have 0 secrets")
        self.assertEqual(result[str(self.user3.id)], 2, "User 3 should have 2 secrets through group membership")

    def test_mixed_access_patterns(self):
        """Test complex scenario with multiple access patterns"""
        
        # Setup datastores with secrets
        Secret_Link.objects.create(
            secret_id=self.secret1.id,
            link_id=uuid.uuid4(),
            parent_datastore_id=self.user1_datastore.id
        )
        
        # Setup shares with secrets
        Share_Tree.objects.create(
            share_id=self.share1.id,
            path="mixedshare1",
            parent_datastore_id=self.user1_datastore.id
        )
        
        Share_Tree.objects.create(
            share_id=self.share2.id,
            path="mixedshare2",
            parent_datastore_id=self.user2_datastore.id
        )
        
        # Create nested share
        link_id = uuid.uuid4()
        create_share_link(
            link_id=link_id,
            share_id=self.share3.id,
            parent_share_id=self.share1.id,
            parent_datastore_id=None
        )
        
        # User2 gets direct access to share1
        User_Share_Right.objects.create(
            user_id=self.user2.id,
            share_id=self.share1.id,
            read=True,
            write=False,
            grant=False,
            accepted=True
        )
        
        # User3 gets access to share2 through group
        group = Group.objects.create(
            name="Mixed Group",
            public_key="5706a5648debec63e86714c8c489f08aee39477487d1b3f39b0bbb05dbd2c649"
        )
        
        User_Group_Membership.objects.create(
            user_id=self.user3.id,
            group_id=group.id,
            accepted=True
        )
        
        Group_Share_Right.objects.create(
            group_id=group.id,
            share_id=self.share2.id,
            read=True,
            write=True,
            grant=False
        )
        
        # Distribute secrets across different locations
        Secret_Link.objects.create(
            secret_id=self.secret2.id,
            link_id=uuid.uuid4(),
            parent_share_id=self.share1.id  # User2 can access this
        )
        
        Secret_Link.objects.create(
            secret_id=self.secret3.id,
            link_id=uuid.uuid4(),
            parent_share_id=self.share3.id  # Nested under share1, user2 can access
        )
        
        Secret_Link.objects.create(
            secret_id=self.secret4.id,
            link_id=uuid.uuid4(),
            parent_share_id=self.share2.id  # User3 can access through group
        )
        
        Secret_Link.objects.create(
            secret_id=self.secret5.id,
            link_id=uuid.uuid4(),
            parent_datastore_id=self.user2_datastore.id  # User2's own datastore
        )
        
        # Test the function
        user_ids = [str(self.user1.id), str(self.user2.id), str(self.user3.id)]
        result = get_secret_counts_for_users(user_ids)
        
        # Assert complex access patterns
        self.assertEqual(result[str(self.user1.id)], 1, "User 1 should have 1 secret from own datastore")
        self.assertEqual(result[str(self.user2.id)], 3, "User 2 should have 3 secrets (1 datastore + 2 share access)")
        self.assertEqual(result[str(self.user3.id)], 1, "User 3 should have 1 secret through group access")

    def test_no_duplicate_secret_counting(self):
        """Test that secrets are not double-counted if accessible through multiple paths"""
        
        # Create shares and trees
        Share_Tree.objects.create(
            share_id=self.share1.id,
            path="dupshare1",
            parent_datastore_id=self.user1_datastore.id
        )
        
        Share_Tree.objects.create(
            share_id=self.share2.id,
            path="dupshare2",  
            parent_datastore_id=self.user1_datastore.id
        )
        
        # User2 gets access to both shares
        User_Share_Right.objects.create(
            user_id=self.user2.id,
            share_id=self.share1.id,
            read=True,
            write=False,
            grant=False,
            accepted=True
        )
        
        User_Share_Right.objects.create(
            user_id=self.user2.id,
            share_id=self.share2.id,
            read=True,
            write=False,
            grant=False,
            accepted=True
        )
        
        # Same secret linked to both shares (duplicate access paths)
        Secret_Link.objects.create(
            secret_id=self.secret1.id,
            link_id=uuid.uuid4(),
            parent_share_id=self.share1.id
        )
        
        Secret_Link.objects.create(
            secret_id=self.secret1.id,  # Same secret!
            link_id=uuid.uuid4(),
            parent_share_id=self.share2.id
        )
        
        # Test the function
        user_ids = [str(self.user2.id)]
        result = get_secret_counts_for_users(user_ids)
        
        # Should count the secret only once despite multiple access paths
        self.assertEqual(result[str(self.user2.id)], 1, "Secret should be counted only once despite multiple access paths")

    def test_empty_user_list(self):
        """Test function with empty user list"""
        result = get_secret_counts_for_users([])
        self.assertEqual(result, {}, "Empty user list should return empty dict")

    def test_nonexistent_user(self):
        """Test function with non-existent user ID"""
        fake_user_id = str(uuid.uuid4())
        result = get_secret_counts_for_users([fake_user_id])
        self.assertEqual(result[fake_user_id], 0, "Non-existent user should have 0 secrets")

    def test_unaccepted_rights_ignored(self):
        """Test that unaccepted share rights are ignored"""
        
        Share_Tree.objects.create(
            share_id=self.share1.id,
            path="unacceptedshare",
            parent_datastore_id=self.user1_datastore.id
        )
        
        # Create unaccepted user share right
        User_Share_Right.objects.create(
            user_id=self.user2.id,
            share_id=self.share1.id,
            read=True,
            write=False,
            grant=False,
            accepted=False  # Not accepted!
        )
        
        # Link secret to share
        Secret_Link.objects.create(
            secret_id=self.secret1.id,
            link_id=uuid.uuid4(),
            parent_share_id=self.share1.id
        )
        
        # Test the function
        user_ids = [str(self.user2.id)]
        result = get_secret_counts_for_users(user_ids)
        
        # Should not count secrets from unaccepted rights
        self.assertEqual(result[str(self.user2.id)], 0, "Unaccepted share rights should be ignored")