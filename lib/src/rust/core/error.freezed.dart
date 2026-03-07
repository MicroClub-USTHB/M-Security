// GENERATED CODE - DO NOT MODIFY BY HAND
// coverage:ignore-file
// ignore_for_file: type=lint
// ignore_for_file: unused_element, deprecated_member_use, deprecated_member_use_from_same_package, use_function_type_syntax_for_parameters, unnecessary_const, avoid_init_to_null, invalid_override_different_default_values_named, prefer_expression_function_bodies, annotate_overrides, invalid_annotation_target, unnecessary_question_mark

part of 'error.dart';

// **************************************************************************
// FreezedGenerator
// **************************************************************************

// dart format off
T _$identity<T>(T value) => value;
/// @nodoc
mixin _$CryptoError {





@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is CryptoError);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'CryptoError()';
}


}

/// @nodoc
class $CryptoErrorCopyWith<$Res>  {
$CryptoErrorCopyWith(CryptoError _, $Res Function(CryptoError) __);
}


/// Adds pattern-matching-related methods to [CryptoError].
extension CryptoErrorPatterns on CryptoError {
/// A variant of `map` that fallback to returning `orElse`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( CryptoError_InvalidKeyLength value)?  invalidKeyLength,TResult Function( CryptoError_InvalidNonce value)?  invalidNonce,TResult Function( CryptoError_EncryptionFailed value)?  encryptionFailed,TResult Function( CryptoError_DecryptionFailed value)?  decryptionFailed,TResult Function( CryptoError_HashingFailed value)?  hashingFailed,TResult Function( CryptoError_KdfFailed value)?  kdfFailed,TResult Function( CryptoError_IoError value)?  ioError,TResult Function( CryptoError_InvalidParameter value)?  invalidParameter,TResult Function( CryptoError_CompressionFailed value)?  compressionFailed,TResult Function( CryptoError_AuthenticationFailed value)?  authenticationFailed,TResult Function( CryptoError_VaultFull value)?  vaultFull,TResult Function( CryptoError_VaultLocked value)?  vaultLocked,TResult Function( CryptoError_SegmentNotFound value)?  segmentNotFound,TResult Function( CryptoError_VaultCorrupted value)?  vaultCorrupted,required TResult orElse(),}){
final _that = this;
switch (_that) {
case CryptoError_InvalidKeyLength() when invalidKeyLength != null:
return invalidKeyLength(_that);case CryptoError_InvalidNonce() when invalidNonce != null:
return invalidNonce(_that);case CryptoError_EncryptionFailed() when encryptionFailed != null:
return encryptionFailed(_that);case CryptoError_DecryptionFailed() when decryptionFailed != null:
return decryptionFailed(_that);case CryptoError_HashingFailed() when hashingFailed != null:
return hashingFailed(_that);case CryptoError_KdfFailed() when kdfFailed != null:
return kdfFailed(_that);case CryptoError_IoError() when ioError != null:
return ioError(_that);case CryptoError_InvalidParameter() when invalidParameter != null:
return invalidParameter(_that);case CryptoError_CompressionFailed() when compressionFailed != null:
return compressionFailed(_that);case CryptoError_AuthenticationFailed() when authenticationFailed != null:
return authenticationFailed(_that);case CryptoError_VaultFull() when vaultFull != null:
return vaultFull(_that);case CryptoError_VaultLocked() when vaultLocked != null:
return vaultLocked(_that);case CryptoError_SegmentNotFound() when segmentNotFound != null:
return segmentNotFound(_that);case CryptoError_VaultCorrupted() when vaultCorrupted != null:
return vaultCorrupted(_that);case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// Callbacks receives the raw object, upcasted.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case final Subclass2 value:
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( CryptoError_InvalidKeyLength value)  invalidKeyLength,required TResult Function( CryptoError_InvalidNonce value)  invalidNonce,required TResult Function( CryptoError_EncryptionFailed value)  encryptionFailed,required TResult Function( CryptoError_DecryptionFailed value)  decryptionFailed,required TResult Function( CryptoError_HashingFailed value)  hashingFailed,required TResult Function( CryptoError_KdfFailed value)  kdfFailed,required TResult Function( CryptoError_IoError value)  ioError,required TResult Function( CryptoError_InvalidParameter value)  invalidParameter,required TResult Function( CryptoError_CompressionFailed value)  compressionFailed,required TResult Function( CryptoError_AuthenticationFailed value)  authenticationFailed,required TResult Function( CryptoError_VaultFull value)  vaultFull,required TResult Function( CryptoError_VaultLocked value)  vaultLocked,required TResult Function( CryptoError_SegmentNotFound value)  segmentNotFound,required TResult Function( CryptoError_VaultCorrupted value)  vaultCorrupted,}){
final _that = this;
switch (_that) {
case CryptoError_InvalidKeyLength():
return invalidKeyLength(_that);case CryptoError_InvalidNonce():
return invalidNonce(_that);case CryptoError_EncryptionFailed():
return encryptionFailed(_that);case CryptoError_DecryptionFailed():
return decryptionFailed(_that);case CryptoError_HashingFailed():
return hashingFailed(_that);case CryptoError_KdfFailed():
return kdfFailed(_that);case CryptoError_IoError():
return ioError(_that);case CryptoError_InvalidParameter():
return invalidParameter(_that);case CryptoError_CompressionFailed():
return compressionFailed(_that);case CryptoError_AuthenticationFailed():
return authenticationFailed(_that);case CryptoError_VaultFull():
return vaultFull(_that);case CryptoError_VaultLocked():
return vaultLocked(_that);case CryptoError_SegmentNotFound():
return segmentNotFound(_that);case CryptoError_VaultCorrupted():
return vaultCorrupted(_that);}
}
/// A variant of `map` that fallback to returning `null`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( CryptoError_InvalidKeyLength value)?  invalidKeyLength,TResult? Function( CryptoError_InvalidNonce value)?  invalidNonce,TResult? Function( CryptoError_EncryptionFailed value)?  encryptionFailed,TResult? Function( CryptoError_DecryptionFailed value)?  decryptionFailed,TResult? Function( CryptoError_HashingFailed value)?  hashingFailed,TResult? Function( CryptoError_KdfFailed value)?  kdfFailed,TResult? Function( CryptoError_IoError value)?  ioError,TResult? Function( CryptoError_InvalidParameter value)?  invalidParameter,TResult? Function( CryptoError_CompressionFailed value)?  compressionFailed,TResult? Function( CryptoError_AuthenticationFailed value)?  authenticationFailed,TResult? Function( CryptoError_VaultFull value)?  vaultFull,TResult? Function( CryptoError_VaultLocked value)?  vaultLocked,TResult? Function( CryptoError_SegmentNotFound value)?  segmentNotFound,TResult? Function( CryptoError_VaultCorrupted value)?  vaultCorrupted,}){
final _that = this;
switch (_that) {
case CryptoError_InvalidKeyLength() when invalidKeyLength != null:
return invalidKeyLength(_that);case CryptoError_InvalidNonce() when invalidNonce != null:
return invalidNonce(_that);case CryptoError_EncryptionFailed() when encryptionFailed != null:
return encryptionFailed(_that);case CryptoError_DecryptionFailed() when decryptionFailed != null:
return decryptionFailed(_that);case CryptoError_HashingFailed() when hashingFailed != null:
return hashingFailed(_that);case CryptoError_KdfFailed() when kdfFailed != null:
return kdfFailed(_that);case CryptoError_IoError() when ioError != null:
return ioError(_that);case CryptoError_InvalidParameter() when invalidParameter != null:
return invalidParameter(_that);case CryptoError_CompressionFailed() when compressionFailed != null:
return compressionFailed(_that);case CryptoError_AuthenticationFailed() when authenticationFailed != null:
return authenticationFailed(_that);case CryptoError_VaultFull() when vaultFull != null:
return vaultFull(_that);case CryptoError_VaultLocked() when vaultLocked != null:
return vaultLocked(_that);case CryptoError_SegmentNotFound() when segmentNotFound != null:
return segmentNotFound(_that);case CryptoError_VaultCorrupted() when vaultCorrupted != null:
return vaultCorrupted(_that);case _:
  return null;

}
}
/// A variant of `when` that fallback to an `orElse` callback.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function( BigInt expected,  BigInt actual)?  invalidKeyLength,TResult Function()?  invalidNonce,TResult Function( String field0)?  encryptionFailed,TResult Function()?  decryptionFailed,TResult Function( String field0)?  hashingFailed,TResult Function( String field0)?  kdfFailed,TResult Function( String field0)?  ioError,TResult Function( String field0)?  invalidParameter,TResult Function( String field0)?  compressionFailed,TResult Function()?  authenticationFailed,TResult Function( BigInt needed,  BigInt available)?  vaultFull,TResult Function()?  vaultLocked,TResult Function( String field0)?  segmentNotFound,TResult Function( String field0)?  vaultCorrupted,required TResult orElse(),}) {final _that = this;
switch (_that) {
case CryptoError_InvalidKeyLength() when invalidKeyLength != null:
return invalidKeyLength(_that.expected,_that.actual);case CryptoError_InvalidNonce() when invalidNonce != null:
return invalidNonce();case CryptoError_EncryptionFailed() when encryptionFailed != null:
return encryptionFailed(_that.field0);case CryptoError_DecryptionFailed() when decryptionFailed != null:
return decryptionFailed();case CryptoError_HashingFailed() when hashingFailed != null:
return hashingFailed(_that.field0);case CryptoError_KdfFailed() when kdfFailed != null:
return kdfFailed(_that.field0);case CryptoError_IoError() when ioError != null:
return ioError(_that.field0);case CryptoError_InvalidParameter() when invalidParameter != null:
return invalidParameter(_that.field0);case CryptoError_CompressionFailed() when compressionFailed != null:
return compressionFailed(_that.field0);case CryptoError_AuthenticationFailed() when authenticationFailed != null:
return authenticationFailed();case CryptoError_VaultFull() when vaultFull != null:
return vaultFull(_that.needed,_that.available);case CryptoError_VaultLocked() when vaultLocked != null:
return vaultLocked();case CryptoError_SegmentNotFound() when segmentNotFound != null:
return segmentNotFound(_that.field0);case CryptoError_VaultCorrupted() when vaultCorrupted != null:
return vaultCorrupted(_that.field0);case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// As opposed to `map`, this offers destructuring.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case Subclass2(:final field2):
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function( BigInt expected,  BigInt actual)  invalidKeyLength,required TResult Function()  invalidNonce,required TResult Function( String field0)  encryptionFailed,required TResult Function()  decryptionFailed,required TResult Function( String field0)  hashingFailed,required TResult Function( String field0)  kdfFailed,required TResult Function( String field0)  ioError,required TResult Function( String field0)  invalidParameter,required TResult Function( String field0)  compressionFailed,required TResult Function()  authenticationFailed,required TResult Function( BigInt needed,  BigInt available)  vaultFull,required TResult Function()  vaultLocked,required TResult Function( String field0)  segmentNotFound,required TResult Function( String field0)  vaultCorrupted,}) {final _that = this;
switch (_that) {
case CryptoError_InvalidKeyLength():
return invalidKeyLength(_that.expected,_that.actual);case CryptoError_InvalidNonce():
return invalidNonce();case CryptoError_EncryptionFailed():
return encryptionFailed(_that.field0);case CryptoError_DecryptionFailed():
return decryptionFailed();case CryptoError_HashingFailed():
return hashingFailed(_that.field0);case CryptoError_KdfFailed():
return kdfFailed(_that.field0);case CryptoError_IoError():
return ioError(_that.field0);case CryptoError_InvalidParameter():
return invalidParameter(_that.field0);case CryptoError_CompressionFailed():
return compressionFailed(_that.field0);case CryptoError_AuthenticationFailed():
return authenticationFailed();case CryptoError_VaultFull():
return vaultFull(_that.needed,_that.available);case CryptoError_VaultLocked():
return vaultLocked();case CryptoError_SegmentNotFound():
return segmentNotFound(_that.field0);case CryptoError_VaultCorrupted():
return vaultCorrupted(_that.field0);}
}
/// A variant of `when` that fallback to returning `null`
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function( BigInt expected,  BigInt actual)?  invalidKeyLength,TResult? Function()?  invalidNonce,TResult? Function( String field0)?  encryptionFailed,TResult? Function()?  decryptionFailed,TResult? Function( String field0)?  hashingFailed,TResult? Function( String field0)?  kdfFailed,TResult? Function( String field0)?  ioError,TResult? Function( String field0)?  invalidParameter,TResult? Function( String field0)?  compressionFailed,TResult? Function()?  authenticationFailed,TResult? Function( BigInt needed,  BigInt available)?  vaultFull,TResult? Function()?  vaultLocked,TResult? Function( String field0)?  segmentNotFound,TResult? Function( String field0)?  vaultCorrupted,}) {final _that = this;
switch (_that) {
case CryptoError_InvalidKeyLength() when invalidKeyLength != null:
return invalidKeyLength(_that.expected,_that.actual);case CryptoError_InvalidNonce() when invalidNonce != null:
return invalidNonce();case CryptoError_EncryptionFailed() when encryptionFailed != null:
return encryptionFailed(_that.field0);case CryptoError_DecryptionFailed() when decryptionFailed != null:
return decryptionFailed();case CryptoError_HashingFailed() when hashingFailed != null:
return hashingFailed(_that.field0);case CryptoError_KdfFailed() when kdfFailed != null:
return kdfFailed(_that.field0);case CryptoError_IoError() when ioError != null:
return ioError(_that.field0);case CryptoError_InvalidParameter() when invalidParameter != null:
return invalidParameter(_that.field0);case CryptoError_CompressionFailed() when compressionFailed != null:
return compressionFailed(_that.field0);case CryptoError_AuthenticationFailed() when authenticationFailed != null:
return authenticationFailed();case CryptoError_VaultFull() when vaultFull != null:
return vaultFull(_that.needed,_that.available);case CryptoError_VaultLocked() when vaultLocked != null:
return vaultLocked();case CryptoError_SegmentNotFound() when segmentNotFound != null:
return segmentNotFound(_that.field0);case CryptoError_VaultCorrupted() when vaultCorrupted != null:
return vaultCorrupted(_that.field0);case _:
  return null;

}
}

}

/// @nodoc


class CryptoError_InvalidKeyLength extends CryptoError {
  const CryptoError_InvalidKeyLength({required this.expected, required this.actual}): super._();
  

 final  BigInt expected;
 final  BigInt actual;

/// Create a copy of CryptoError
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$CryptoError_InvalidKeyLengthCopyWith<CryptoError_InvalidKeyLength> get copyWith => _$CryptoError_InvalidKeyLengthCopyWithImpl<CryptoError_InvalidKeyLength>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is CryptoError_InvalidKeyLength&&(identical(other.expected, expected) || other.expected == expected)&&(identical(other.actual, actual) || other.actual == actual));
}


@override
int get hashCode => Object.hash(runtimeType,expected,actual);

@override
String toString() {
  return 'CryptoError.invalidKeyLength(expected: $expected, actual: $actual)';
}


}

/// @nodoc
abstract mixin class $CryptoError_InvalidKeyLengthCopyWith<$Res> implements $CryptoErrorCopyWith<$Res> {
  factory $CryptoError_InvalidKeyLengthCopyWith(CryptoError_InvalidKeyLength value, $Res Function(CryptoError_InvalidKeyLength) _then) = _$CryptoError_InvalidKeyLengthCopyWithImpl;
@useResult
$Res call({
 BigInt expected, BigInt actual
});




}
/// @nodoc
class _$CryptoError_InvalidKeyLengthCopyWithImpl<$Res>
    implements $CryptoError_InvalidKeyLengthCopyWith<$Res> {
  _$CryptoError_InvalidKeyLengthCopyWithImpl(this._self, this._then);

  final CryptoError_InvalidKeyLength _self;
  final $Res Function(CryptoError_InvalidKeyLength) _then;

/// Create a copy of CryptoError
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? expected = null,Object? actual = null,}) {
  return _then(CryptoError_InvalidKeyLength(
expected: null == expected ? _self.expected : expected // ignore: cast_nullable_to_non_nullable
as BigInt,actual: null == actual ? _self.actual : actual // ignore: cast_nullable_to_non_nullable
as BigInt,
  ));
}


}

/// @nodoc


class CryptoError_InvalidNonce extends CryptoError {
  const CryptoError_InvalidNonce(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is CryptoError_InvalidNonce);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'CryptoError.invalidNonce()';
}


}




/// @nodoc


class CryptoError_EncryptionFailed extends CryptoError {
  const CryptoError_EncryptionFailed(this.field0): super._();
  

 final  String field0;

/// Create a copy of CryptoError
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$CryptoError_EncryptionFailedCopyWith<CryptoError_EncryptionFailed> get copyWith => _$CryptoError_EncryptionFailedCopyWithImpl<CryptoError_EncryptionFailed>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is CryptoError_EncryptionFailed&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'CryptoError.encryptionFailed(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $CryptoError_EncryptionFailedCopyWith<$Res> implements $CryptoErrorCopyWith<$Res> {
  factory $CryptoError_EncryptionFailedCopyWith(CryptoError_EncryptionFailed value, $Res Function(CryptoError_EncryptionFailed) _then) = _$CryptoError_EncryptionFailedCopyWithImpl;
@useResult
$Res call({
 String field0
});




}
/// @nodoc
class _$CryptoError_EncryptionFailedCopyWithImpl<$Res>
    implements $CryptoError_EncryptionFailedCopyWith<$Res> {
  _$CryptoError_EncryptionFailedCopyWithImpl(this._self, this._then);

  final CryptoError_EncryptionFailed _self;
  final $Res Function(CryptoError_EncryptionFailed) _then;

/// Create a copy of CryptoError
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(CryptoError_EncryptionFailed(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class CryptoError_DecryptionFailed extends CryptoError {
  const CryptoError_DecryptionFailed(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is CryptoError_DecryptionFailed);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'CryptoError.decryptionFailed()';
}


}




/// @nodoc


class CryptoError_HashingFailed extends CryptoError {
  const CryptoError_HashingFailed(this.field0): super._();
  

 final  String field0;

/// Create a copy of CryptoError
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$CryptoError_HashingFailedCopyWith<CryptoError_HashingFailed> get copyWith => _$CryptoError_HashingFailedCopyWithImpl<CryptoError_HashingFailed>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is CryptoError_HashingFailed&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'CryptoError.hashingFailed(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $CryptoError_HashingFailedCopyWith<$Res> implements $CryptoErrorCopyWith<$Res> {
  factory $CryptoError_HashingFailedCopyWith(CryptoError_HashingFailed value, $Res Function(CryptoError_HashingFailed) _then) = _$CryptoError_HashingFailedCopyWithImpl;
@useResult
$Res call({
 String field0
});




}
/// @nodoc
class _$CryptoError_HashingFailedCopyWithImpl<$Res>
    implements $CryptoError_HashingFailedCopyWith<$Res> {
  _$CryptoError_HashingFailedCopyWithImpl(this._self, this._then);

  final CryptoError_HashingFailed _self;
  final $Res Function(CryptoError_HashingFailed) _then;

/// Create a copy of CryptoError
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(CryptoError_HashingFailed(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class CryptoError_KdfFailed extends CryptoError {
  const CryptoError_KdfFailed(this.field0): super._();
  

 final  String field0;

/// Create a copy of CryptoError
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$CryptoError_KdfFailedCopyWith<CryptoError_KdfFailed> get copyWith => _$CryptoError_KdfFailedCopyWithImpl<CryptoError_KdfFailed>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is CryptoError_KdfFailed&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'CryptoError.kdfFailed(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $CryptoError_KdfFailedCopyWith<$Res> implements $CryptoErrorCopyWith<$Res> {
  factory $CryptoError_KdfFailedCopyWith(CryptoError_KdfFailed value, $Res Function(CryptoError_KdfFailed) _then) = _$CryptoError_KdfFailedCopyWithImpl;
@useResult
$Res call({
 String field0
});




}
/// @nodoc
class _$CryptoError_KdfFailedCopyWithImpl<$Res>
    implements $CryptoError_KdfFailedCopyWith<$Res> {
  _$CryptoError_KdfFailedCopyWithImpl(this._self, this._then);

  final CryptoError_KdfFailed _self;
  final $Res Function(CryptoError_KdfFailed) _then;

/// Create a copy of CryptoError
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(CryptoError_KdfFailed(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class CryptoError_IoError extends CryptoError {
  const CryptoError_IoError(this.field0): super._();
  

 final  String field0;

/// Create a copy of CryptoError
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$CryptoError_IoErrorCopyWith<CryptoError_IoError> get copyWith => _$CryptoError_IoErrorCopyWithImpl<CryptoError_IoError>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is CryptoError_IoError&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'CryptoError.ioError(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $CryptoError_IoErrorCopyWith<$Res> implements $CryptoErrorCopyWith<$Res> {
  factory $CryptoError_IoErrorCopyWith(CryptoError_IoError value, $Res Function(CryptoError_IoError) _then) = _$CryptoError_IoErrorCopyWithImpl;
@useResult
$Res call({
 String field0
});




}
/// @nodoc
class _$CryptoError_IoErrorCopyWithImpl<$Res>
    implements $CryptoError_IoErrorCopyWith<$Res> {
  _$CryptoError_IoErrorCopyWithImpl(this._self, this._then);

  final CryptoError_IoError _self;
  final $Res Function(CryptoError_IoError) _then;

/// Create a copy of CryptoError
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(CryptoError_IoError(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class CryptoError_InvalidParameter extends CryptoError {
  const CryptoError_InvalidParameter(this.field0): super._();
  

 final  String field0;

/// Create a copy of CryptoError
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$CryptoError_InvalidParameterCopyWith<CryptoError_InvalidParameter> get copyWith => _$CryptoError_InvalidParameterCopyWithImpl<CryptoError_InvalidParameter>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is CryptoError_InvalidParameter&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'CryptoError.invalidParameter(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $CryptoError_InvalidParameterCopyWith<$Res> implements $CryptoErrorCopyWith<$Res> {
  factory $CryptoError_InvalidParameterCopyWith(CryptoError_InvalidParameter value, $Res Function(CryptoError_InvalidParameter) _then) = _$CryptoError_InvalidParameterCopyWithImpl;
@useResult
$Res call({
 String field0
});




}
/// @nodoc
class _$CryptoError_InvalidParameterCopyWithImpl<$Res>
    implements $CryptoError_InvalidParameterCopyWith<$Res> {
  _$CryptoError_InvalidParameterCopyWithImpl(this._self, this._then);

  final CryptoError_InvalidParameter _self;
  final $Res Function(CryptoError_InvalidParameter) _then;

/// Create a copy of CryptoError
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(CryptoError_InvalidParameter(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class CryptoError_CompressionFailed extends CryptoError {
  const CryptoError_CompressionFailed(this.field0): super._();
  

 final  String field0;

/// Create a copy of CryptoError
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$CryptoError_CompressionFailedCopyWith<CryptoError_CompressionFailed> get copyWith => _$CryptoError_CompressionFailedCopyWithImpl<CryptoError_CompressionFailed>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is CryptoError_CompressionFailed&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'CryptoError.compressionFailed(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $CryptoError_CompressionFailedCopyWith<$Res> implements $CryptoErrorCopyWith<$Res> {
  factory $CryptoError_CompressionFailedCopyWith(CryptoError_CompressionFailed value, $Res Function(CryptoError_CompressionFailed) _then) = _$CryptoError_CompressionFailedCopyWithImpl;
@useResult
$Res call({
 String field0
});




}
/// @nodoc
class _$CryptoError_CompressionFailedCopyWithImpl<$Res>
    implements $CryptoError_CompressionFailedCopyWith<$Res> {
  _$CryptoError_CompressionFailedCopyWithImpl(this._self, this._then);

  final CryptoError_CompressionFailed _self;
  final $Res Function(CryptoError_CompressionFailed) _then;

/// Create a copy of CryptoError
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(CryptoError_CompressionFailed(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class CryptoError_AuthenticationFailed extends CryptoError {
  const CryptoError_AuthenticationFailed(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is CryptoError_AuthenticationFailed);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'CryptoError.authenticationFailed()';
}


}




/// @nodoc


class CryptoError_VaultFull extends CryptoError {
  const CryptoError_VaultFull({required this.needed, required this.available}): super._();
  

 final  BigInt needed;
 final  BigInt available;

/// Create a copy of CryptoError
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$CryptoError_VaultFullCopyWith<CryptoError_VaultFull> get copyWith => _$CryptoError_VaultFullCopyWithImpl<CryptoError_VaultFull>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is CryptoError_VaultFull&&(identical(other.needed, needed) || other.needed == needed)&&(identical(other.available, available) || other.available == available));
}


@override
int get hashCode => Object.hash(runtimeType,needed,available);

@override
String toString() {
  return 'CryptoError.vaultFull(needed: $needed, available: $available)';
}


}

/// @nodoc
abstract mixin class $CryptoError_VaultFullCopyWith<$Res> implements $CryptoErrorCopyWith<$Res> {
  factory $CryptoError_VaultFullCopyWith(CryptoError_VaultFull value, $Res Function(CryptoError_VaultFull) _then) = _$CryptoError_VaultFullCopyWithImpl;
@useResult
$Res call({
 BigInt needed, BigInt available
});




}
/// @nodoc
class _$CryptoError_VaultFullCopyWithImpl<$Res>
    implements $CryptoError_VaultFullCopyWith<$Res> {
  _$CryptoError_VaultFullCopyWithImpl(this._self, this._then);

  final CryptoError_VaultFull _self;
  final $Res Function(CryptoError_VaultFull) _then;

/// Create a copy of CryptoError
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? needed = null,Object? available = null,}) {
  return _then(CryptoError_VaultFull(
needed: null == needed ? _self.needed : needed // ignore: cast_nullable_to_non_nullable
as BigInt,available: null == available ? _self.available : available // ignore: cast_nullable_to_non_nullable
as BigInt,
  ));
}


}

/// @nodoc


class CryptoError_VaultLocked extends CryptoError {
  const CryptoError_VaultLocked(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is CryptoError_VaultLocked);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'CryptoError.vaultLocked()';
}


}




/// @nodoc


class CryptoError_SegmentNotFound extends CryptoError {
  const CryptoError_SegmentNotFound(this.field0): super._();
  

 final  String field0;

/// Create a copy of CryptoError
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$CryptoError_SegmentNotFoundCopyWith<CryptoError_SegmentNotFound> get copyWith => _$CryptoError_SegmentNotFoundCopyWithImpl<CryptoError_SegmentNotFound>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is CryptoError_SegmentNotFound&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'CryptoError.segmentNotFound(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $CryptoError_SegmentNotFoundCopyWith<$Res> implements $CryptoErrorCopyWith<$Res> {
  factory $CryptoError_SegmentNotFoundCopyWith(CryptoError_SegmentNotFound value, $Res Function(CryptoError_SegmentNotFound) _then) = _$CryptoError_SegmentNotFoundCopyWithImpl;
@useResult
$Res call({
 String field0
});




}
/// @nodoc
class _$CryptoError_SegmentNotFoundCopyWithImpl<$Res>
    implements $CryptoError_SegmentNotFoundCopyWith<$Res> {
  _$CryptoError_SegmentNotFoundCopyWithImpl(this._self, this._then);

  final CryptoError_SegmentNotFound _self;
  final $Res Function(CryptoError_SegmentNotFound) _then;

/// Create a copy of CryptoError
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(CryptoError_SegmentNotFound(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class CryptoError_VaultCorrupted extends CryptoError {
  const CryptoError_VaultCorrupted(this.field0): super._();
  

 final  String field0;

/// Create a copy of CryptoError
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$CryptoError_VaultCorruptedCopyWith<CryptoError_VaultCorrupted> get copyWith => _$CryptoError_VaultCorruptedCopyWithImpl<CryptoError_VaultCorrupted>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is CryptoError_VaultCorrupted&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'CryptoError.vaultCorrupted(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $CryptoError_VaultCorruptedCopyWith<$Res> implements $CryptoErrorCopyWith<$Res> {
  factory $CryptoError_VaultCorruptedCopyWith(CryptoError_VaultCorrupted value, $Res Function(CryptoError_VaultCorrupted) _then) = _$CryptoError_VaultCorruptedCopyWithImpl;
@useResult
$Res call({
 String field0
});




}
/// @nodoc
class _$CryptoError_VaultCorruptedCopyWithImpl<$Res>
    implements $CryptoError_VaultCorruptedCopyWith<$Res> {
  _$CryptoError_VaultCorruptedCopyWithImpl(this._self, this._then);

  final CryptoError_VaultCorrupted _self;
  final $Res Function(CryptoError_VaultCorrupted) _then;

/// Create a copy of CryptoError
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(CryptoError_VaultCorrupted(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

// dart format on
