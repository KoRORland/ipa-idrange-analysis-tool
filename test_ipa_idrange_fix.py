'''UNIT TESTS FOR ipa_idrange_fix.py'''
import unittest

from ipa_idrange_fix import IDRange, IDentity, IPAIDRangeFix

from ipa_idrange_fix import (
    range_overlap_check,
    range_overlap_check_idrange,
    newrange_overlap_check,
    get_ipa_local_ranges,
    ranges_overlap_check,
    propose_rid_ranges,
    propose_rid_base,
    max_rid,
    check_rid_base,
    get_ranges_no_base,
    group_identities_by_threshold,
    separate_under1000,
    separate_ranges_and_outliers,
    round_idrange,
    get_rangename_base,
    get_rangename,
    propose_range,
)


class TestIDRange(unittest.TestCase):
    def test_count(self):
        """Test the count method of IDRange class"""
        pass

    def test_repr(self):
        """Test the __repr__ method of IDRange class"""
        pass

    def test_eq(self):
        """Test the __eq__ method of IDRange class"""
        pass


class TestIDentity(unittest.TestCase):
    def test_repr(self):
        """Test the __repr__ method of IDentity class"""
        pass

    def test_eq(self):
        """Test the __eq__ method of IDentity class"""
        pass


class TestIPAIDRangeFix(unittest.TestCase):
    '''Test for IPAIDRangeFix'''
    def setUp(self):
        """Set up any necessary objects or configurations for the tests"""
        self.testidranges = []
        self.testidranges.append(
            IDRange(
                name="default",
                size=200000,
                first_id=100000000,
                base_rid=1000,
                secondary_base_rid=100000000,
                type="ipa-local",
                dn="cn=default,cn=ranges,cn=etc,dc=example,dc=com",
                suffix="dc=example,dc=com",
            )
        )
        self.testidranges.append(
            IDRange(
                name="subid",
                size=2147352576,
                first_id=2147483648,
                base_rid=2147283648,
                type="ipa-adtrust",
                dn="cn=default,cn=ranges,cn=etc,dc=example,dc=com",
                suffix="dc=example,dc=com",
            )
        )

    def tearDown(self):
        """Clean up any resources used by the tests"""
        pass

    def test_evaluate_ranges(self):
        """Test the evaluate_ranges method of IPAIDRangeFix class"""

        pass

    def test_evaluate_identities(self):
        """Test the evaluate_identities method of IPAIDRangeFix class"""
        pass

    def test_print_intentions(self):
        """Test the print_intentions method of IPAIDRangeFix class"""
        pass

    def test_draw_ascii_table(self):
        """Test the draw_ascii_table function"""
        pass

    def test_read_ranges(self):
        """Test the read_ranges function"""
        pass

    def test_read_outofrange_identities(self):
        """Test the read_outofrange_identities function"""
        pass

    def test_read_identity(self):
        """Test the read_identity function"""
        pass

    def test_get_outofrange_filter(self):
        """Test the get_outofrange_filter function"""
        pass

    def test_apply_ridbases(self):
        """Test the apply_ridbases function"""
        pass

    def test_create_range(self):
        """Test the create_range function"""
        pass

    def test_get_ipa_local_ranges(self):
        """Test the get_ipa_local_ranges function"""
        expectedranges = [
            IDRange(
                name="default",
                size=200000,
                first_id=100000000,
                base_rid=1000,
                secondary_base_rid=100000000,
                type="ipa-local",
                dn="cn=default,cn=ranges,cn=etc,dc=example,dc=com",
                suffix="dc=example,dc=com",
            )
        ]
        self.assertEqual(get_ipa_local_ranges(
            self.testidranges),
            expectedranges
            )

    def test_range_overlap_check(self):
        """Test the range_overlap_check function"""
        # simple overlap
        self.assertFalse(range_overlap_check(1, 10, 5, 15))
        self.assertFalse(range_overlap_check(5, 15, 1, 10))
        # touching
        self.assertFalse(range_overlap_check(1, 5, 5, 10))
        self.assertFalse(range_overlap_check(5, 10, 1, 5))
        # full overlap
        self.assertFalse(range_overlap_check(1, 10, 1, 10))
        # conpletely inside
        self.assertFalse(range_overlap_check(1, 10, 2, 9))
        self.assertFalse(range_overlap_check(2, 9, 1, 10))
        # no overlap
        self.assertTrue(range_overlap_check(1, 10, 15, 20))

    def test_range_overlap_check_idrange(self):
        """Test the range_overlap_check_idrange function"""
        self.assertFalse(range_overlap_check_idrange(
            IDRange(size=10, first_id=1),
            IDRange(size=10, first_id=5),
        ))
        self.assertTrue(range_overlap_check_idrange(
            self.testidranges[0],
            self.testidranges[1]
        ))

    def test_newrange_overlap_check(self):
        """Test the newrange_overlap_check function"""
        self.assertFalse(newrange_overlap_check(
            self.testidranges,
            IDRange(size=10, first_id=100000000),
        ))
        self.assertTrue(newrange_overlap_check(
            self.testidranges,
            IDRange(size=10, first_id=100200000),
        ))
        self.assertFalse(newrange_overlap_check(
            self.testidranges,
            IDRange(size=2147352576, first_id=100200000),
        ))
        self.assertFalse(newrange_overlap_check(
            self.testidranges,
            IDRange(size=10, first_id=99999991),
        ))
        self.assertTrue(newrange_overlap_check(
            self.testidranges,
            IDRange(size=10, first_id=99999990),
        ))

    def test_ranges_overlap_check(self):
        """Test the ranges_overlap_check function"""
        pass

    def test_propose_rid_ranges(self):
        """Test the propose_rid_ranges function"""
        pass

    def test_propose_rid_base(self):
        """Test the propose_rid_base function"""
        pass

    def test_max_rid(self):
        """Test the max_rid function"""
        pass

    def test_check_rid_base(self):
        """Test the check_rid_base function"""
        pass

    def test_get_ranges_no_base(self):
        """Test the get_ranges_no_base function"""
        pass

    def test_group_identities_by_threshold(self):
        """Test the group_identities_by_threshold function"""
        pass

    def test_separate_under1000(self):
        """Test the separate_under1000 function"""
        pass

    def test_separate_ranges_and_outliers(self):
        """Test the separate_ranges_and_outliers function"""
        pass

    def test_round_idrange(self):
        """Test the round_idrange function"""
        pass

    def test_get_rangename_base(self):
        """Test the get_rangename_base function"""
        pass

    def test_get_rangename(self):
        """Test the get_rangename function"""
        pass

    def test_propose_range(self):
        """Test the propose_range function"""
        pass

    if __name__ == "__main__":
        unittest.main()
