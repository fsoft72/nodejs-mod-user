/*
 * This file has been generated by flow2code
 * See: https://flow.liwe.org
 */

import { ILRequest, ILResponse, ILError, ILiWE } from '../../liwe/types';
import { send_error, send_ok, typed_dict } from "../../liwe/utils";
import { locale_load } from '../../liwe/locale';

import { perms } from '../../liwe/auth';

import {
	// endpoints function
	delete_user_admin_del, delete_user_info_del, get_user_2fa_start, get_user_admin_get, get_user_admin_list,
	get_user_domain_invitation_accept, get_user_domains_list, get_user_faces_get, get_user_faces_modules, get_user_find,
	get_user_logout, get_user_me, get_user_perms_get, get_user_register_activate, get_user_remove_me,
	get_user_test_create, patch_user_admin_fields, patch_user_admin_update, patch_user_change_password, patch_user_profile,
	patch_user_set_billing, patch_user_set_bio, patch_user_update, post_user_2fa_verify, post_user_admin_add,
	post_user_admin_change_password, post_user_admin_relogin, post_user_anonymous, post_user_avatar, post_user_del_app,
	post_user_facerec_add, post_user_info_add, post_user_login, post_user_login_2fa, post_user_login_metamask,
	post_user_login_refresh, post_user_login_remote, post_user_password_forgot, post_user_password_forgot_app, post_user_password_reset,
	post_user_perms_set, post_user_register, post_user_register_app, post_user_tag, post_user_token,
	post_user_upload2face,
	// functions
	user_db_init, user_facerec_get, user_get_by_group, user_session_create, user_session_del,
	user_session_get, users_list,
} from './methods';

import {
	User, User2FA, User2FAKeys, UserActivationCode, UserActivationCodeKeys,
	UserDetails, UserDetailsKeys, UserDomain, UserDomainKeys, UserFaceRec,
	UserFaceRecKeys, UserKeys, UserPerms, UserPermsKeys, UserRegistration,
	UserRegistrationKeys, UserSessionData, UserSessionDataKeys, UserSmall, UserSmallKeys,
} from './types';

/*=== f2c_start __header ===*/
import { SystemDomainPublic } from '../system/types';
/*=== f2c_end __header ===*/

export const init = ( liwe: ILiWE ) => {
	const app = liwe.app;

	console.log( "    - user " );

	liwe.cfg.app.languages.map( ( l ) => locale_load( "user", l ) );
	user_db_init ( liwe );

	app.post ( '/api/user/admin/add', perms( [ "user.create" ] ), ( req: ILRequest, res: ILResponse ) => {
		const { email, password, username, name, lastname, perms, enabled, language, group, ___errors } = typed_dict( req.body, [
			{ name: "email", type: "string", required: true },
			{ name: "password", type: "string", required: true },
			{ name: "username", type: "string", required: true },
			{ name: "name", type: "string" },
			{ name: "lastname", type: "string" },
			{ name: "perms", type: "string[]" },
			{ name: "enabled", type: "boolean" },
			{ name: "language", type: "string" },
			{ name: "group", type: "string" }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		post_user_admin_add ( req, email, password, username, name, lastname, perms, enabled, language, group, ( err: ILError, user: User ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { user } );
		} );
	} );

	app.patch ( '/api/user/admin/update', perms( [ "user.create" ] ), ( req: ILRequest, res: ILResponse ) => {
		const { id, email, password, name, lastname, enabled, level, language, ___errors } = typed_dict( req.body, [
			{ name: "id", type: "string", required: true },
			{ name: "email", type: "string" },
			{ name: "password", type: "string" },
			{ name: "name", type: "string" },
			{ name: "lastname", type: "string" },
			{ name: "enabled", type: "boolean" },
			{ name: "level", type: "number" },
			{ name: "language", type: "string" }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		patch_user_admin_update ( req, id, email, password, name, lastname, enabled, level, language, ( err: ILError, user: User ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { user } );
		} );
	} );

	app.delete ( '/api/user/admin/del', perms( [ "user.create" ] ), ( req: ILRequest, res: ILResponse ) => {
		const { id_user, ___errors } = typed_dict( req.body, [
			{ name: "id_user", type: "string", required: true }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		delete_user_admin_del ( req, id_user, ( err: ILError, id_user: string ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { id_user } );
		} );
	} );

	app.patch ( '/api/user/admin/fields', perms( [ "user.create" ] ), ( req: ILRequest, res: ILResponse ) => {
		const { id, data, ___errors } = typed_dict( req.body, [
			{ name: "id", type: "string", required: true },
			{ name: "data", type: "any", required: true }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		patch_user_admin_fields ( req, id, data, ( err: ILError, user: User ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { user } );
		} );
	} );

	app.post ( '/api/user/register', ( req: ILRequest, res: ILResponse ) => {
		const { email, password, recaptcha, name, lastname, phone, username, group, ___errors } = typed_dict( req.body, [
			{ name: "email", type: "string", required: true },
			{ name: "password", type: "string", required: true },
			{ name: "recaptcha", type: "string", required: true },
			{ name: "name", type: "string" },
			{ name: "lastname", type: "string" },
			{ name: "phone", type: "string" },
			{ name: "username", type: "string" },
			{ name: "group", type: "string" }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		post_user_register ( req, email, password, recaptcha, name, lastname, phone, username, group, ( err: ILError, uac: UserActivationCode ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { uac } );
		} );
	} );

	app.patch ( '/api/user/update', perms( [ "is-logged" ] ), ( req: ILRequest, res: ILResponse ) => {
		const { email, password, name, lastname, username, group, phone, ___errors } = typed_dict( req.body, [
			{ name: "email", type: "string" },
			{ name: "password", type: "string" },
			{ name: "name", type: "string" },
			{ name: "lastname", type: "string" },
			{ name: "username", type: "string" },
			{ name: "group", type: "string" },
			{ name: "phone", type: "string" }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		patch_user_update ( req, email, password, name, lastname, username, group, phone, ( err: ILError, user: User ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { user } );
		} );
	} );

	app.post ( '/api/user/avatar', perms( [ "is-logged" ] ), ( req: ILRequest, res: ILResponse ) => {
		const { avatar, ___errors } = typed_dict( req.body, [
			{ name: "avatar", type: "File", required: true }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		post_user_avatar ( req, avatar, ( err: ILError, user: User ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { user } );
		} );
	} );

	app.post ( '/api/user/facerec/add', perms( [ "is-logged" ] ), ( req: ILRequest, res: ILResponse ) => {
		const { face, ___errors } = typed_dict( req.body, [
			{ name: "face", type: "File", required: true }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		post_user_facerec_add ( req, face, ( err: ILError, facerec: UserFaceRec ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { facerec } );
		} );
	} );

	app.post ( '/api/user/password-forgot', ( req: ILRequest, res: ILResponse ) => {
		const { email, recaptcha, ___errors } = typed_dict( req.body, [
			{ name: "email", type: "string", required: true },
			{ name: "recaptcha", type: "string", required: true }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		post_user_password_forgot ( req, email, recaptcha, ( err: ILError, uac: string ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { uac } );
		} );
	} );

	app.post ( '/api/user/password-reset', ( req: ILRequest, res: ILResponse ) => {
		const { email, code, password, ___errors } = typed_dict( req.body, [
			{ name: "email", type: "string", required: true },
			{ name: "code", type: "string", required: true },
			{ name: "password", type: "string", required: true }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		post_user_password_reset ( req, email, code, password, ( err: ILError, ok: boolean ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { ok } );
		} );
	} );

	app.get ( '/api/user/register/activate/:code', ( req: ILRequest, res: ILResponse ) => {
		const { code, ___errors } = typed_dict( req.params, [
			{ name: "code", type: "string", required: true }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		get_user_register_activate ( req, code, ( err: ILError, user: User ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { user } );
		} );
	} );

	app.post ( '/api/user/tag', perms( [ "user.tag", "user.create" ] ), ( req: ILRequest, res: ILResponse ) => {
		const { id_user, tags, ___errors } = typed_dict( req.body, [
			{ name: "id_user", type: "string", required: true },
			{ name: "tags", type: "string[]", required: true }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		post_user_tag ( req, id_user, tags, ( err: ILError, user: User ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { user } );
		} );
	} );

	app.post ( '/api/user/token', ( req: ILRequest, res: ILResponse ) => {
		const { username, password, ___errors } = typed_dict( req.body, [
			{ name: "username", type: "string", required: true },
			{ name: "password", type: "string", required: true }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		post_user_token ( req, username, password, ( err: ILError, __plain__: UserSessionData ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { ...__plain__ } );
		} );
	} );

	app.post ( '/api/user/login', ( req: ILRequest, res: ILResponse ) => {
		const { password, email, username, recaptcha, challenge, ___errors } = typed_dict( req.body, [
			{ name: "password", type: "string", required: true },
			{ name: "email", type: "string" },
			{ name: "username", type: "string" },
			{ name: "recaptcha", type: "string" },
			{ name: "challenge", type: "string" }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		post_user_login ( req, password, email, username, recaptcha, challenge, ( err: ILError, __plain__: UserSessionData ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { ...__plain__ } );
		} );
	} );

	app.post ( '/api/user/login/remote', ( req: ILRequest, res: ILResponse ) => {
		const { email, name, challenge, avatar, ___errors } = typed_dict( req.body, [
			{ name: "email", type: "string", required: true },
			{ name: "name", type: "string", required: true },
			{ name: "challenge", type: "string", required: true },
			{ name: "avatar", type: "string" }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		post_user_login_remote ( req, email, name, challenge, avatar, ( err: ILError, __plain__: UserSessionData ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { ...__plain__ } );
		} );
	} );

	app.get ( '/api/user/admin/list', perms( [ "user.create", "user.group_owner" ] ), ( req: ILRequest, res: ILResponse ) => {
		const { tag, ___errors } = typed_dict( req.query as any, [
			{ name: "tag", type: "string" }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		get_user_admin_list ( req, tag, ( err: ILError, users: User ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { users } );
		} );
	} );

	app.get ( '/api/user/logout', perms( [ "is-logged" ] ), ( req: ILRequest, res: ILResponse ) => {
		

		get_user_logout ( req, ( err: ILError, ok: boolean ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { ok } );
		} );
	} );

	app.get ( '/api/user/me', perms( [ "is-logged" ] ), ( req: ILRequest, res: ILResponse ) => {
		

		get_user_me ( req, ( err: ILError, user: User ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { user } );
		} );
	} );

	app.post ( '/api/user/perms_set', perms( [ "user.perms" ] ), ( req: ILRequest, res: ILResponse ) => {
		const { id_user, perms, ___errors } = typed_dict( req.body, [
			{ name: "id_user", type: "string", required: true },
			{ name: "perms", type: "UserPerms", required: true }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		post_user_perms_set ( req, id_user, perms, ( err: ILError, ok: boolean ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { ok } );
		} );
	} );

	app.post ( '/api/user/info_add', perms( [ "is-logged" ] ), ( req: ILRequest, res: ILResponse ) => {
		const { key, data, ___errors } = typed_dict( req.body, [
			{ name: "key", type: "string", required: true },
			{ name: "data", type: "any", required: true }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		post_user_info_add ( req, key, data, ( err: ILError, ok: boolean ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { ok } );
		} );
	} );

	app.delete ( '/api/user/info_del', perms( [ "is-logged" ] ), ( req: ILRequest, res: ILResponse ) => {
		const { key, ___errors } = typed_dict( req.body, [
			{ name: "key", type: "string", required: true }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		delete_user_info_del ( req, key, ( err: ILError, ok: boolean ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { ok } );
		} );
	} );

	app.patch ( '/api/user/profile', perms( [ "is-logged" ] ), ( req: ILRequest, res: ILResponse ) => {
		const { name, lastname, phone, email, addr_street, addr_nr, addr_zip, addr_city, addr_state, addr_country, facebook, twitter, linkedin, instagram, website, ___errors } = typed_dict( req.body, [
			{ name: "name", type: "string" },
			{ name: "lastname", type: "string" },
			{ name: "phone", type: "string" },
			{ name: "email", type: "string" },
			{ name: "addr_street", type: "string" },
			{ name: "addr_nr", type: "string" },
			{ name: "addr_zip", type: "string" },
			{ name: "addr_city", type: "string" },
			{ name: "addr_state", type: "string" },
			{ name: "addr_country", type: "string" },
			{ name: "facebook", type: "string" },
			{ name: "twitter", type: "string" },
			{ name: "linkedin", type: "string" },
			{ name: "instagram", type: "string" },
			{ name: "website", type: "string" }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		patch_user_profile ( req, name, lastname, phone, email, addr_street, addr_nr, addr_zip, addr_city, addr_state, addr_country, facebook, twitter, linkedin, instagram, website, ( err: ILError, user: User ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { user } );
		} );
	} );

	app.get ( '/api/user/test/create', perms( [ "user.create" ] ), ( req: ILRequest, res: ILResponse ) => {
		

		get_user_test_create ( req, ( err: ILError, user: User ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { user } );
		} );
	} );

	app.patch ( '/api/user/change/password', perms( [ "is-logged" ] ), ( req: ILRequest, res: ILResponse ) => {
		const { old_password, new_password, recaptcha, ___errors } = typed_dict( req.body, [
			{ name: "old_password", type: "string", required: true },
			{ name: "new_password", type: "string", required: true },
			{ name: "recaptcha", type: "string", required: true }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		patch_user_change_password ( req, old_password, new_password, recaptcha, ( err: ILError, ok: boolean ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { ok } );
		} );
	} );

	app.patch ( '/api/user/set/bio', perms( [ "is-logged" ] ), ( req: ILRequest, res: ILResponse ) => {
		const { tagline, bio, ___errors } = typed_dict( req.body, [
			{ name: "tagline", type: "string" },
			{ name: "bio", type: "string" }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		patch_user_set_bio ( req, tagline, bio, ( err: ILError, user: User ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { user } );
		} );
	} );

	app.patch ( '/api/user/set/billing', perms( [ "is-logged" ] ), ( req: ILRequest, res: ILResponse ) => {
		const { address, nr, name, city, zip, state, country, company_name, fiscal_code, vat_number, sdi, pec, ___errors } = typed_dict( req.body, [
			{ name: "address", type: "string" },
			{ name: "nr", type: "string" },
			{ name: "name", type: "string" },
			{ name: "city", type: "string" },
			{ name: "zip", type: "string" },
			{ name: "state", type: "string" },
			{ name: "country", type: "string" },
			{ name: "company_name", type: "string" },
			{ name: "fiscal_code", type: "string" },
			{ name: "vat_number", type: "string" },
			{ name: "sdi", type: "string" },
			{ name: "pec", type: "string" }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		patch_user_set_billing ( req, address, nr, name, city, zip, state, country, company_name, fiscal_code, vat_number, sdi, pec, ( err: ILError, user: User ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { user } );
		} );
	} );

	app.post ( '/api/user/login/metamask', ( req: ILRequest, res: ILResponse ) => {
		const { address, challenge, ___errors } = typed_dict( req.body, [
			{ name: "address", type: "string", required: true },
			{ name: "challenge", type: "string", required: true }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		post_user_login_metamask ( req, address, challenge, ( err: ILError, __plain__: UserSessionData ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { ...__plain__ } );
		} );
	} );

	app.get ( '/api/user/admin/get', perms( [ "user.create" ] ), ( req: ILRequest, res: ILResponse ) => {
		const { id, email, name, lastname, ___errors } = typed_dict( req.query as any, [
			{ name: "id", type: "string" },
			{ name: "email", type: "string" },
			{ name: "name", type: "string" },
			{ name: "lastname", type: "string" }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		get_user_admin_get ( req, id, email, name, lastname, ( err: ILError, user: User ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { user } );
		} );
	} );

	app.get ( '/api/user/remove/me', perms( [ "is-logged" ] ), ( req: ILRequest, res: ILResponse ) => {
		

		get_user_remove_me ( req, ( err: ILError, ok: boolean ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { ok } );
		} );
	} );

	app.get ( '/api/user/perms/get', perms( [ "user.perms" ] ), ( req: ILRequest, res: ILResponse ) => {
		const { id_user, ___errors } = typed_dict( req.query as any, [
			{ name: "id_user", type: "string", required: true }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		get_user_perms_get ( req, id_user, ( err: ILError, ok: boolean ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { ok } );
		} );
	} );

	app.get ( '/api/user/faces/get', perms( [ "is-logged" ] ), ( req: ILRequest, res: ILResponse ) => {
		const { id_user, ___errors } = typed_dict( req.query as any, [
			{ name: "id_user", type: "string" }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		get_user_faces_get ( req, id_user, ( err: ILError, faces: UserFaceRec ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { faces } );
		} );
	} );

	app.post ( '/api/user/upload2face', perms( [ "is-logged" ] ), ( req: ILRequest, res: ILResponse ) => {
		const { id_upload, id_user, ___errors } = typed_dict( req.body, [
			{ name: "id_upload", type: "string", required: true },
			{ name: "id_user", type: "string" }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		post_user_upload2face ( req, id_upload, id_user, ( err: ILError, face: UserFaceRec ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { face } );
		} );
	} );

	app.get ( '/api/user/faces/modules', ( req: ILRequest, res: ILResponse ) => {
		

		get_user_faces_modules ( req, ( err: ILError, ok: boolean ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { ok } );
		} );
	} );

	app.post ( '/api/user/anonymous', ( req: ILRequest, res: ILResponse ) => {
		const { ts, challenge, ___errors } = typed_dict( req.body, [
			{ name: "ts", type: "string", required: true },
			{ name: "challenge", type: "string", required: true }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		post_user_anonymous ( req, ts, challenge, ( err: ILError, user: User ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { user } );
		} );
	} );

	app.post ( '/api/user/register/app', ( req: ILRequest, res: ILResponse ) => {
		const { email, password, challenge, name, lastname, phone, username, group, ___errors } = typed_dict( req.body, [
			{ name: "email", type: "string", required: true },
			{ name: "password", type: "string", required: true },
			{ name: "challenge", type: "string", required: true },
			{ name: "name", type: "string" },
			{ name: "lastname", type: "string" },
			{ name: "phone", type: "string" },
			{ name: "username", type: "string" },
			{ name: "group", type: "string" }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		post_user_register_app ( req, email, password, challenge, name, lastname, phone, username, group, ( err: ILError, uac: UserActivationCode ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { uac } );
		} );
	} );

	app.get ( '/api/user/find', perms( [ "is-logged" ] ), ( req: ILRequest, res: ILResponse ) => {
		const { search, ___errors } = typed_dict( req.query as any, [
			{ name: "search", type: "string" }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		get_user_find ( req, search, ( err: ILError, user: UserDetails ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { user } );
		} );
	} );

	app.post ( '/api/user/password-forgot/app', ( req: ILRequest, res: ILResponse ) => {
		const { username, challenge, ___errors } = typed_dict( req.body, [
			{ name: "username", type: "string", required: true },
			{ name: "challenge", type: "string", required: true }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		post_user_password_forgot_app ( req, username, challenge, ( err: ILError, uac: UserActivationCode ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { uac } );
		} );
	} );

	app.post ( '/api/user/del/app', perms( [ "is-logged" ] ), ( req: ILRequest, res: ILResponse ) => {
		const { id_user, username, challenge, ___errors } = typed_dict( req.body, [
			{ name: "id_user", type: "string", required: true },
			{ name: "username", type: "string", required: true },
			{ name: "challenge", type: "string", required: true }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		post_user_del_app ( req, id_user, username, challenge, ( err: ILError, ok: boolean ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { ok } );
		} );
	} );

	app.get ( '/api/user/2fa/start', perms( [ "is-logged" ] ), ( req: ILRequest, res: ILResponse ) => {
		

		get_user_2fa_start ( req, ( err: ILError, url: string ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { url } );
		} );
	} );

	app.post ( '/api/user/login/2fa', ( req: ILRequest, res: ILResponse ) => {
		const { id, code, nonce, ___errors } = typed_dict( req.body, [
			{ name: "id", type: "string", required: true },
			{ name: "code", type: "string", required: true },
			{ name: "nonce", type: "string", required: true }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		post_user_login_2fa ( req, id, code, nonce, ( err: ILError, __plain__: UserSessionData ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { ...__plain__ } );
		} );
	} );

	app.post ( '/api/user/2fa/verify', perms( [ "is-logged" ] ), ( req: ILRequest, res: ILResponse ) => {
		const { code, ___errors } = typed_dict( req.body, [
			{ name: "code", type: "string", required: true }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		post_user_2fa_verify ( req, code, ( err: ILError, ok: boolean ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { ok } );
		} );
	} );

	app.post ( '/api/user/admin/change/password', perms( [ "user.password" ] ), ( req: ILRequest, res: ILResponse ) => {
		const { id_user, password, ___errors } = typed_dict( req.body, [
			{ name: "id_user", type: "string", required: true },
			{ name: "password", type: "string", required: true }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		post_user_admin_change_password ( req, id_user, password, ( err: ILError, ok: boolean ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { ok } );
		} );
	} );

	app.post ( '/api/user/admin/relogin', perms( [ "user.change_identity" ] ), ( req: ILRequest, res: ILResponse ) => {
		const { id_user, ___errors } = typed_dict( req.body, [
			{ name: "id_user", type: "string", required: true }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		post_user_admin_relogin ( req, id_user, ( err: ILError, __plain__: UserSessionData ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { ...__plain__ } );
		} );
	} );

	app.get ( '/api/user/domain/invitation/accept', perms( [ "is-logged" ] ), ( req: ILRequest, res: ILResponse ) => {
		const { invitation, ___errors } = typed_dict( req.query as any, [
			{ name: "invitation", type: "string", required: true }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		get_user_domain_invitation_accept ( req, invitation, ( err: ILError, ok: boolean ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { ok } );
		} );
	} );

	app.get ( '/api/user/domains/list', perms( [ "is-logged" ] ), ( req: ILRequest, res: ILResponse ) => {
		

		get_user_domains_list ( req, ( err: ILError, domains: UserDomain ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { domains } );
		} );
	} );

	app.post ( '/api/user/login/refresh', ( req: ILRequest, res: ILResponse ) => {
		const { token, ___errors } = typed_dict( req.body, [
			{ name: "token", type: "string", required: true }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		post_user_login_refresh ( req, token, ( err: ILError, __plain__: UserSessionData ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { ...__plain__ } );
		} );
	} );

};
