/**
 * @param {{username:String,owner:String,password:String,firstLoginAttempt:Date,lastLoginAttempt:Date, framework_db:String}} _authObj
 * @properties={typeid:24,uuid:"CACF4ECC-3601-4B60-BC14-6774BA3BB00C"}
 * @AllowToRunInFind
 */
function ma_sec_checkUser(_authObj) {
		
	//query's the user from the database
	var query = '	SELECT			sec_user.user_id, \
									sec_user.user_locked, \
									sow.license_amount, \
									sow.owner_id \
					FROM			sec_user, \
									sec_owner sow \
					WHERE (EXISTS \
									(SELECT	* \
									FROM	sec_user_org, \
											sec_organization, \
											sec_owner \
									WHERE	sec_user.user_id = sec_user_org.user_id \
									AND		sec_user_org.organization_id = sec_organization.organization_id \
									AND		sec_organization.owner_id = sec_owner.owner_id \
									AND		sec_owner.owner_id = sow.owner_id \
									AND		sec_owner.name = ?) \
					OR (sec_user.flag_super_administrator = 1 \
					AND (EXISTS \
									(SELECT	* \
									FROM	sec_owner \
									WHERE	sec_owner.owner_id = sow.owner_id \
									AND		sec_owner.name = ?)))) \
					AND			sec_user.user_name = ?;';	
	var args = new Array();
	args[0] = _authObj.owner
	args[1] = _authObj.owner
	args[2] = _authObj.username
	var dataset = databaseManager.getDataSetByQuery(_authObj.framework_db, query, args, -1);
	var _return = new Object()
	_return.success = false
		
	if(dataset.getValue(1, 2) != 1) {
		
		_return.license = dataset.getValue(1, 3);
		_return.owner_id = dataset.getValue(1, 4);
		_return.user_id =  dataset.getValue(1, 1);
		
		/** @type {String} */
		var _owner = _return.owner_id;
		// check if owner has enough licenses for this user to log in
		var _clientCount = application.getClientCountForInfo(_owner)
		if (_clientCount >= _return.license) {
			globals.svy_sec_registerLoginAttempt(dataset.getValue(1,1), false, 'svy.fr.dlg.max_licenses', false, _authObj.framework_db);
			_return.error = 'svy.fr.dlg.max_licenses'
		} else {
			globals.svy_sec_registerLoginAttempt(dataset.getValue(1,1), true, null, false, _authObj.framework_db);
			_return.success = true;
		}
		
		return _return 
	} 
	else if (dataset.getValue(1,1) && dataset.getValue(1,2) == 1) //user is locked
	{
		// globals.svy_sec_registerLoginAttempt(dataset.getValue(1,1), false, 'User was already locked', false);
		_return.error = 'svy.fr.dlg.user_locked'
		return _return
	} else {
		// when a user uses a wrong password, we keep track in the user table
		
		// get the record of the user
		/** @type {JSFoundset<db:/svy_framework/sec_user>} */
		var _fs_user = databaseManager.getFoundSet(_authObj.framework_db, 'sec_user');
		_fs_user.addFoundSetFilterParam('owner_id', '=', dataset.getValue(1, 6));
		_fs_user.addFoundSetFilterParam('user_name', '=', _authObj.username);
		_fs_user.loadAllRecords();

		if (databaseManager.hasRecords(_fs_user)) {
			globals.svy_sec_registerLoginAttempt(dataset.getValue(1, 1), false, 'svy.fr.dlg.wrong_password', true, _authObj.framework_db);
			
			if(!_fs_user.times_wrong_login) {
				_fs_user.times_wrong_login = 1;
			} else {
				_fs_user.times_wrong_login += 1;	
			}
			
			// when a user logs in with a wrong password too many times (and within the timespan) then lock the user
			if(dataset.getValue(1, 7) && dataset.getValue(1, 7) <= _fs_user.times_wrong_login) {
				if (dataset.getValue(1, 9)) {
					var _timespanBeforeLock = dataset.getValue(1, 9);
					/** @type {Number} */
					var _passwordTimesWrong = dataset.getValue(1, 7);
					
					/** @type {JSFoundset<db:/svy_framework/sec_user_login_attempt>} */
					var _fs_loginAttempt = databaseManager.getFoundSet(_authObj.framework_db, 'sec_user_login_attempt');
					_fs_loginAttempt.find();
					_fs_loginAttempt.user_id = dataset.getValue(1, 1);
					_fs_loginAttempt.reason_include_timespan = 1;
					if (_fs_loginAttempt.search() >= dataset.getValue(1, 7)) {
						_fs_loginAttempt.sort('attempt_datetime desc');
						_fs_loginAttempt.setSelectedIndex(_passwordTimesWrong);
						
						if (new Date().valueOf() - _fs_loginAttempt.attempt_datetime.valueOf() >= _timespanBeforeLock * 60000) {
							return _return;
						}
					} else {
						return _return;
					}
				}
				
				_fs_user.user_locked = 1;
				_fs_user.user_locked_datetime = new Date();
				databaseManager.saveData();
				
				_return.error = 'svy.fr.dlg.user_locked';
				return _return;
			}
		}
		return _return;
	}
}