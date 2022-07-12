
import { ILRequest, ILResponse, ILApplication, ILiweConfig, ILError, ILiWE } from '../../liwe/types';
import { send_error, send_ok, typed_dict } from "../../liwe/utils";
import { locale_load } from '../../liwe/locale';

import { perms } from '../../liwe/auth';

import {
	post_user_admin_add, patch_user_admin_update, delete_user_admin_del, patch_user_admin_fields, post_user_register, patch_user_update, post_user_avatar, post_user_facerec_add, post_user_password_forgot, post_user_password_reset, get_user_register_activate, post_user_tag, post_user_token, post_user_login, post_user_login_remote, get_user_admin_list, get_user_logout, get_user_me, post_user_perms_set, post_user_info_add, delete_user_info_del, patch_user_profile, get_user_test_create, patch_user_change_password, patch_user_set_bio, patch_user_set_billing, post_user_login_metamask, get_user_admin_get, get_user_remove_me, user_db_init, user_facerec_get, user_session_del, user_session_get, user_session_create
} from './methods';

import {
	User, UserActivationCode, UserFaceRec, UserPerms, UserRegistration, UserSessionData
} from './types';

/*=== d2r_start __header ===*/

/*=== d2r_end __header ===*/

/* === USER API === */
export const init = ( liwe: ILiWE ) => {
	const app = liwe.app;

	console.log( "    - User " );

	liwe.cfg.app.languages.map( ( l ) => locale_load( "user", l ) );
	user_db_init ( liwe );


	app.post ( "/api/user/admin/add", perms( [ "user.create" ] ), ( req: ILRequest, res: ILResponse ) => {
		const { email, password, name, lastname, perms, enabled, language, ___errors } = typed_dict( req.body, [
			{ name: "email", type: "string", required: true },
			{ name: "password", type: "string", required: true },
			{ name: "name", type: "string" },
			{ name: "lastname", type: "string" },
			{ name: "perms", type: "string[]" },
			{ name: "enabled", type: "boolean" },
			{ name: "language", type: "string" }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		post_user_admin_add ( req,email, password, name, lastname, perms, enabled, language,  ( err: ILError, user: User ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { user } );
		} );
	} );

	app.patch ( "/api/user/admin/update", perms( [ "user.create" ] ), ( req: ILRequest, res: ILResponse ) => {
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

		patch_user_admin_update ( req,id, email, password, name, lastname, enabled, level, language,  ( err: ILError, user: User ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { user } );
		} );
	} );

	app.delete ( "/api/user/admin/del", perms( [ "user.create" ] ), ( req: ILRequest, res: ILResponse ) => {
		const { id_user, ___errors } = typed_dict( req.body, [
			{ name: "id_user", type: "string", required: true }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		delete_user_admin_del ( req,id_user,  ( err: ILError, id_user: string ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { id_user } );
		} );
	} );

	app.patch ( "/api/user/admin/fields", perms( [ "user.create" ] ), ( req: ILRequest, res: ILResponse ) => {
		const { id, data, ___errors } = typed_dict( req.body, [
			{ name: "id", type: "string", required: true },
			{ name: "data", type: "any", required: true }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		patch_user_admin_fields ( req,id, data,  ( err: ILError, user: User ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { user } );
		} );
	} );

	app.post ( "/api/user/register", ( req: ILRequest, res: ILResponse ) => {
		const { email, password, recaptcha, name, lastname, ___errors } = typed_dict( req.body, [
			{ name: "email", type: "string", required: true },
			{ name: "password", type: "string", required: true },
			{ name: "recaptcha", type: "string", required: true },
			{ name: "name", type: "string" },
			{ name: "lastname", type: "string" }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		post_user_register ( req,email, password, recaptcha, name, lastname,  ( err: ILError, uac: UserActivationCode ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { uac } );
		} );
	} );

	app.patch ( "/api/user/update", perms( [ "is-logged" ] ), ( req: ILRequest, res: ILResponse ) => {
		const { email, password, name, lastname, ___errors } = typed_dict( req.body, [
			{ name: "email", type: "string" },
			{ name: "password", type: "string" },
			{ name: "name", type: "string" },
			{ name: "lastname", type: "string" }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		patch_user_update ( req,email, password, name, lastname,  ( err: ILError, user: User ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { user } );
		} );
	} );

	app.post ( "/api/user/avatar", perms( [ "is-logged" ] ), ( req: ILRequest, res: ILResponse ) => {
		const { avatar, ___errors } = typed_dict( req.body, [
			
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		post_user_avatar ( req,avatar,  ( err: ILError, user: User ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { user } );
		} );
	} );

	app.post ( "/api/user/facerec/add", perms( [ "is-logged" ] ), ( req: ILRequest, res: ILResponse ) => {
		const { face, ___errors } = typed_dict( req.body, [
			
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		post_user_facerec_add ( req,face,  ( err: ILError, facerec: UserFaceRec ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { facerec } );
		} );
	} );

	app.post ( "/api/user/password-forgot", ( req: ILRequest, res: ILResponse ) => {
		const { email, recaptcha, ___errors } = typed_dict( req.body, [
			{ name: "email", type: "string", required: true },
			{ name: "recaptcha", type: "string", required: true }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		post_user_password_forgot ( req,email, recaptcha,  ( err: ILError, uac: string ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { uac } );
		} );
	} );

	app.post ( "/api/user/password-reset", ( req: ILRequest, res: ILResponse ) => {
		const { email, code, password, ___errors } = typed_dict( req.body, [
			{ name: "email", type: "string", required: true },
			{ name: "code", type: "string", required: true },
			{ name: "password", type: "string", required: true }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		post_user_password_reset ( req,email, code, password,  ( err: ILError, ok: boolean ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { ok } );
		} );
	} );

	app.get ( "/api/user/register/activate/:code", ( req: ILRequest, res: ILResponse ) => {
		const { code, ___errors } = typed_dict( req.params, [
			{ name: "code", type: "string", required: true }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		get_user_register_activate ( req,code,  ( err: ILError, user: User ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { user } );
		} );
	} );

	app.post ( "/api/user/tag", perms( [ "user.tag", "user.create" ] ), ( req: ILRequest, res: ILResponse ) => {
		const { id_user, tags, ___errors } = typed_dict( req.body, [
			{ name: "id_user", type: "string", required: true },
			{ name: "tags", type: "string[]", required: true }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		post_user_tag ( req,id_user, tags,  ( err: ILError, user: User ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { user } );
		} );
	} );

	app.post ( "/api/user/token", ( req: ILRequest, res: ILResponse ) => {
		const { username, password, ___errors } = typed_dict( req.body, [
			{ name: "username", type: "string", required: true },
			{ name: "password", type: "string", required: true }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		post_user_token ( req,username, password,  ( err: ILError, tmp: UserSessionData ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { ...tmp } );
		} );
	} );

	app.post ( "/api/user/login", ( req: ILRequest, res: ILResponse ) => {
		const { email, password, recaptcha, ___errors } = typed_dict( req.body, [
			{ name: "email", type: "string", required: true },
			{ name: "password", type: "string", required: true },
			{ name: "recaptcha", type: "string", required: true }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		post_user_login ( req,email, password, recaptcha,  ( err: ILError, tmp: UserSessionData ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { ...tmp } );
		} );
	} );

	app.post ( "/api/user/login/remote", ( req: ILRequest, res: ILResponse ) => {
		const { email, name, challenge, avatar, ___errors } = typed_dict( req.body, [
			{ name: "email", type: "string", required: true },
			{ name: "name", type: "string", required: true },
			{ name: "challenge", type: "string", required: true },
			{ name: "avatar", type: "string" }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		post_user_login_remote ( req,email, name, challenge, avatar,  ( err: ILError, tmp: UserSessionData ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { ...tmp } );
		} );
	} );

	app.get ( "/api/user/admin/list", perms( [ "user.create" ] ), ( req: ILRequest, res: ILResponse ) => {
		const { tag, ___errors } = typed_dict( req.query as any, [
			{ name: "tag", type: "string" }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		get_user_admin_list ( req,tag,  ( err: ILError, users: User[] ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { users } );
		} );
	} );

	app.get ( "/api/user/logout", ( req: ILRequest, res: ILResponse ) => {
		
		
		get_user_logout ( req, ( err: ILError, ok: boolean ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { ok } );
		} );
	} );

	app.get ( "/api/user/me", ( req: ILRequest, res: ILResponse ) => {
		
		
		get_user_me ( req, ( err: ILError, user: User ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { user } );
		} );
	} );

	app.post ( "/api/user/perms_set", perms( [ "user.perms" ] ), ( req: ILRequest, res: ILResponse ) => {
		const { id_user, perms, ___errors } = typed_dict( req.body, [
			{ name: "id_user", type: "string", required: true },
			{ name: "perms", type: "UserPerms", required: true }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		post_user_perms_set ( req,id_user, perms,  ( err: ILError, ok: boolean ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { ok } );
		} );
	} );

	app.post ( "/api/user/info_add", perms( [ "is-logged" ] ), ( req: ILRequest, res: ILResponse ) => {
		const { key, data, ___errors } = typed_dict( req.body, [
			{ name: "key", type: "string", required: true },
			{ name: "data", type: "any", required: true }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		post_user_info_add ( req,key, data,  ( err: ILError, ok: boolean ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { ok } );
		} );
	} );

	app.delete ( "/api/user/info_del", perms( [ "is-logged" ] ), ( req: ILRequest, res: ILResponse ) => {
		const { key, ___errors } = typed_dict( req.body, [
			{ name: "key", type: "string", required: true }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		delete_user_info_del ( req,key,  ( err: ILError, ok: boolean ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { ok } );
		} );
	} );

	app.patch ( "/api/user/profile", perms( [ "is-logged" ] ), ( req: ILRequest, res: ILResponse ) => {
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

		patch_user_profile ( req,name, lastname, phone, email, addr_street, addr_nr, addr_zip, addr_city, addr_state, addr_country, facebook, twitter, linkedin, instagram, website,  ( err: ILError, user: User ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { user } );
		} );
	} );

	app.get ( "/api/user/test/create", ( req: ILRequest, res: ILResponse ) => {
		
		
		get_user_test_create ( req, ( err: ILError, user: User ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { user } );
		} );
	} );

	app.patch ( "/api/user/change/password", perms( [ "is-logged" ] ), ( req: ILRequest, res: ILResponse ) => {
		const { old_password, new_password, recaptcha, ___errors } = typed_dict( req.body, [
			{ name: "old_password", type: "string", required: true },
			{ name: "new_password", type: "string", required: true },
			{ name: "recaptcha", type: "string", required: true }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		patch_user_change_password ( req,old_password, new_password, recaptcha,  ( err: ILError, ok: boolean ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { ok } );
		} );
	} );

	app.patch ( "/api/user/set/bio", perms( [ "is-logged" ] ), ( req: ILRequest, res: ILResponse ) => {
		const { tagline, bio, ___errors } = typed_dict( req.body, [
			{ name: "tagline", type: "string" },
			{ name: "bio", type: "string" }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		patch_user_set_bio ( req,tagline, bio,  ( err: ILError, user: User ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { user } );
		} );
	} );

	app.patch ( "/api/user/set/billing", perms( [ "is-logged" ] ), ( req: ILRequest, res: ILResponse ) => {
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

		patch_user_set_billing ( req,address, nr, name, city, zip, state, country, company_name, fiscal_code, vat_number, sdi, pec,  ( err: ILError, user: User ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { user } );
		} );
	} );

	app.post ( "/api/user/login/metamask", ( req: ILRequest, res: ILResponse ) => {
		const { address, challenge, ___errors } = typed_dict( req.body, [
			{ name: "address", type: "string", required: true },
			{ name: "challenge", type: "string", required: true }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		post_user_login_metamask ( req,address, challenge,  ( err: ILError, tmp: UserSessionData ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { ...tmp } );
		} );
	} );

	app.get ( "/api/user/admin/get", perms( [ "user.create" ] ), ( req: ILRequest, res: ILResponse ) => {
		const { id, email, name, lastname, ___errors } = typed_dict( req.query as any, [
			{ name: "id", type: "string" },
			{ name: "email", type: "string" },
			{ name: "name", type: "string" },
			{ name: "lastname", type: "string" }
		] );

		if ( ___errors.length ) return send_error ( res, { message: `Parameters error: ${___errors.join ( ', ' )}` } );

		get_user_admin_get ( req,id, email, name, lastname,  ( err: ILError, user: User ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { user } );
		} );
	} );

	app.get ( "/api/user/remove/me", ( req: ILRequest, res: ILResponse ) => {
		
		
		get_user_remove_me ( req, ( err: ILError, ok: boolean ) => {
			if ( err ) return send_error( res, err );

			send_ok( res, { ok } );
		} );
	} );

}
