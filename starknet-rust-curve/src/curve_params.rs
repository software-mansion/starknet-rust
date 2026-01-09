use starknet_types_core::curve::AffinePoint;
use starknet_types_core::felt::Felt;

/// EC order of the STARK curve for ECDSA. Equals to
/// `0x0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f`.
pub const EC_ORDER: Felt = Felt::from_raw([
    369_010_039_416_812_937,
    9,
    1_143_265_896_874_747_514,
    8_939_893_405_601_011_193,
]);

/// The alpha parameter of the STARK curve. Equals to
/// `0x0000000000000000000000000000000000000000000000000000000000000001`.
///
/// The alpha parameter is used in the curve definition as:
///
/// ```markdown
/// y^2 = x^3 + alpha * x + beta
/// ```
pub const ALPHA: Felt = Felt::from_raw([
    576_460_752_303_422_960,
    18_446_744_073_709_551_615,
    18_446_744_073_709_551_615,
    18_446_744_073_709_551_585,
]);

/// The beta parameter of the STARK curve. Equals to
/// `0x06f21413efbe40de150e596d72f7a8c5609ad26c15c915c1f4cdfcb99cee9e89`.
///
/// The beta parameter is used in the curve definition as:
///
/// ```markdown
/// y^2 = x^3 + alpha * x + beta
/// ```
pub const BETA: Felt = Felt::from_raw([
    88_155_977_965_380_735,
    12_360_725_113_329_547_591,
    7_432_612_994_240_712_710,
    3_863_487_492_851_900_874,
]);

/// Generator point of the STARK curve.
///
/// Coordinates:
///
/// - x: `0x01ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca`
/// - y: `0x005668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f`
pub const GENERATOR: AffinePoint = AffinePoint::new_unchecked(
    Felt::from_raw([
        232_005_955_912_912_577,
        299_981_207_024_966_779,
        5_884_444_832_209_845_738,
        14_484_022_957_141_291_997,
    ]),
    Felt::from_raw([
        405_578_048_423_154_473,
        18_147_424_675_297_964_973,
        664_812_301_889_158_119,
        6_241_159_653_446_987_914,
    ]),
);

/// Shift point of the STARK curve.
///
/// Coordinates:
///
/// - x: `0x049ee3eba8c1600700ee1b87eb599f16716b0b1022947733551fde4050ca6804`
/// - y: `0x03ca0cfe4b3bc6ddf346d49d06ea0ed34e621062c0e056c1d0405d266e10268a`
pub const SHIFT_POINT: AffinePoint = AffinePoint::new_unchecked(
    Felt::from_raw([
        316_327_189_671_755_572,
        1_641_324_389_046_377_921,
        7_739_989_395_386_261_137,
        1_933_903_796_324_928_314,
    ]),
    Felt::from_raw([
        81_375_596_133_053_150,
        4_798_858_472_748_676_776,
        12_587_053_260_418_384_210,
        14_252_083_571_674_603_243,
    ]),
);

/// The P0 constant of the STARK curve.
///
/// Coordinates:
///
/// - x: `0x0234287dcbaffe7f969c748655fca9e58fa8120b6d56eb0c1080d17957ebe47b`
/// - y: `0x03b056f100f96fb21e889527d41f4e39940135dd7a6c94cc6ed0268ee89e5615`
pub const PEDERSEN_P0: AffinePoint = AffinePoint::new_unchecked(
    Felt::from_raw([
        241_691_544_791_834_578,
        518_715_844_721_862_878,
        13_758_484_295_849_329_960,
        3_602_345_268_353_203_007,
    ]),
    Felt::from_raw([
        368_891_789_801_938_570,
        433_857_700_841_878_496,
        13_001_553_326_386_915_570,
        13_441_546_676_070_136_227,
    ]),
);

/// The P1 constant of the STARK curve.
///
/// Coordinates:
///
/// - x: `0x04fa56f376c83db33f9dab2656558f3399099ec1de5e3018b7a6932dba8aa378`
/// - y: `0x03fa0984c931c9e38113e0c0e47e4401562761f92a7a23b45168f4e80ff5b54d`
pub const PEDERSEN_P1: AffinePoint = AffinePoint::new_unchecked(
    Felt::from_raw([
        253_000_153_565_733_272,
        10_043_949_394_709_899_044,
        12_382_025_591_154_462_459,
        16_491_878_934_996_302_286,
    ]),
    Felt::from_raw([
        285_630_633_187_035_523,
        5_191_292_837_124_484_988,
        2_545_498_000_137_298_346,
        13_950_428_914_333_633_429,
    ]),
);

/// The P2 constant of the STARK curve.
///
/// Coordinates:
///
/// - x: `0x04ba4cc166be8dec764910f75b45f74b40c690c74709e90f3aa372f0bd2d6997`
/// - y: `0x0040301cf5c1751f4b971e46c4ede85fcac5c59a5ce5ae7c48151f27b24b219c`
pub const PEDERSEN_P2: AffinePoint = AffinePoint::new_unchecked(
    Felt::from_raw([
        338_510_149_841_406_402,
        12_916_675_983_929_588_442,
        18_195_981_508_842_736_832,
        1_203_723_169_299_412_240,
    ]),
    Felt::from_raw([
        161_068_411_212_710_156,
        11_088_962_269_971_685_343,
        11_743_524_503_750_604_092,
        12_352_616_181_161_700_245,
    ]),
);

/// The P3 constant of the STARK curve.
///
/// Coordinates:
///
/// - x: `0x054302dcb0e6cc1c6e44cca8f61a63bb2ca65048d53fb325d36ff12c49a58202`
/// - y: `0x01b77b3e37d13504b348046268d8ae25ce98ad783c25561a879dcc77e99c2426`
pub const PEDERSEN_P3: AffinePoint = AffinePoint::new_unchecked(
    Felt::from_raw([
        425_493_972_656_615_276,
        299_781_701_614_706_065,
        10_664_803_185_694_787_051,
        1_145_636_535_101_238_356,
    ]),
    Felt::from_raw([
        345_457_391_846_365_716,
        6_033_691_581_221_864_148,
        4_428_713_245_976_508_844,
        8_187_986_478_389_849_302,
    ]),
);
