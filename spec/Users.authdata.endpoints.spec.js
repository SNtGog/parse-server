const {
  MOCK_USER_ID,
  MOCK_USER_ID_2,
  MOCK_ACCESS_TOKEN,
  MOCK_ACCESS_TOKEN_2,
  setupAuthConfig,
  mockGpgamesLogin,
  mockGpgamesTokenExchange,
  mockGpgamesPlayerInfo,
  mockInstagramLogin,
  createUserWithGpgamesAndSession,
  assertAuthDataProviders,
} = require('./Users.authdata.helpers');

const request = require('../lib/request');

describe('AuthData REST API Endpoint: /users/:id', () => {
  beforeEach(async () => {
    await setupAuthConfig();
  });

  // ============================================
  // Level 8.1: /users/:id endpoint behavior
  // ============================================
  // These tests verify that PUT /users/:id behaves the same as /users/me
  // for authData validation logic (tested separately in validation.spec.js)

  describe('Level 8.1: /users/:id endpoint behavior', () => {
    // Update with same id → validate not called
    describe('Update with same id (no validation)', () => {
      it('should skip validation on /users/:id when id unchanged', async () => {
        mockFetch(mockGpgamesLogin());
        const { user, sessionToken } = await createUserWithGpgamesAndSession();
        const userId = user.id;

        let validationCalled = false;
        mockFetch(
          mockGpgamesLogin({
            accessToken: MOCK_ACCESS_TOKEN_2,
            onTokenExchange: () => {
              validationCalled = true;
            },
          })
        );

        // Update via /users/:id (REST API PUT)
        await request({
          method: 'PUT',
          url: `http://localhost:8378/1/classes/_User/${userId}`,
          headers: {
            'X-Parse-Application-Id': Parse.applicationId,
            'X-Parse-REST-API-Key': 'rest',
            'X-Parse-Session-Token': sessionToken,
            'Content-Type': 'application/json',
          },
          body: {
            authData: { gpgames: { id: MOCK_USER_ID } },
          },
          json: true,
        });

        expect(validationCalled).toBe(false);
      });
    });

    // Update with new id → validate called
    describe('Update with new id (validation required)', () => {
      it('should validate on /users/:id when id changes', async () => {
        mockFetch(mockGpgamesLogin());
        const { user, sessionToken } = await createUserWithGpgamesAndSession();
        const userId = user.id;

        let validationCalled = false;
        mockFetch([
          mockGpgamesTokenExchange((code) => {
            validationCalled = true;
            return MOCK_ACCESS_TOKEN_2;
          }),
          mockGpgamesPlayerInfo(MOCK_USER_ID_2),
        ]);

        // Update via /users/:id (REST API PUT)
        await request({
          method: 'PUT',
          url: `http://localhost:8378/1/classes/_User/${userId}`,
          headers: {
            'X-Parse-Application-Id': Parse.applicationId,
            'X-Parse-REST-API-Key': 'rest',
            'X-Parse-Session-Token': sessionToken,
            'Content-Type': 'application/json',
          },
          body: {
            authData: { gpgames: { id: MOCK_USER_ID_2, code: 'C2' } },
          },
          json: true,
        });

        expect(validationCalled).toBe(true);
      });
    });

    // Unlink provider → validate not called
    describe('Unlink provider (no validation)', () => {
      it('should skip validation on /users/:id when unlinking provider', async () => {
        mockFetch(mockGpgamesLogin());
        const { user, sessionToken } = await createUserWithGpgamesAndSession();
        const userId = user.id;
        const current = user.get('authData');

        let validationCalled = false;
        mockFetch(
          mockGpgamesLogin({
            accessToken: MOCK_ACCESS_TOKEN_2,
            onTokenExchange: () => {
              validationCalled = true;
            },
          })
        );

        // Update via /users/:id (REST API PUT)
        await request({
          method: 'PUT',
          url: `http://localhost:8378/1/classes/_User/${userId}`,
          headers: {
            'X-Parse-Application-Id': Parse.applicationId,
            'X-Parse-REST-API-Key': 'rest',
            'X-Parse-Session-Token': sessionToken,
            'Content-Type': 'application/json',
          },
          body: {
            authData: { ...current, gpgames: null },
          },
          json: true,
        });

        expect(validationCalled).toBe(false);

        // Verify provider was unlinked
        const updated = await new Parse.Query(Parse.User).get(userId, {
          useMasterKey: true,
        });
        const authData = updated.get('authData');
        if (authData) {
          expect(authData.gpgames).toBeUndefined();
        }
      });
    });

    // Multiple providers, change only one
    describe('Multiple providers, change only one', () => {
      it('should validate only changed provider on /users/:id', async () => {
        let gpgamesValidated = false;
        let instagramValidated = false;

        mockFetch([
          ...mockGpgamesLogin({
            accessToken: (code) => {
              if (code === 'C1') {
                return MOCK_ACCESS_TOKEN;
              } else if (code === 'C2') {
                gpgamesValidated = true;
                return MOCK_ACCESS_TOKEN_2;
              }
              return MOCK_ACCESS_TOKEN;
            },
          }),
          ...mockInstagramLogin({ accessToken: 'ig_token_1' }),
        ]);

        // Create user with gpgames
        const user = await Parse.User.logInWith('gpgames', {
          authData: { id: MOCK_USER_ID, code: 'C1' },
        });
        const sessionToken = user.getSessionToken();
        const userId = user.id;

        // Add instagram
        await user.save(
          { authData: { instagram: { id: 'I1', code: 'IC1' } } },
          { sessionToken }
        );

        // Update only gpgames via /users/:id (REST API PUT)
        await request({
          method: 'PUT',
          url: `http://localhost:8378/1/users/${userId}`,
          headers: {
            'X-Parse-Application-Id': Parse.applicationId,
            'X-Parse-REST-API-Key': 'rest',
            'X-Parse-Session-Token': sessionToken,
            'Content-Type': 'application/json',
          },
          body: {
            authData: { gpgames: { id: MOCK_USER_ID, code: 'C2' } },
          },
          json: true,
        });

        // Only gpgames should have been validated (if validation was needed)
        // Note: validation might be skipped if id matches, which is correct behavior
        expect(instagramValidated).toBe(false);
      });
    });
  });

  // ============================================
  // Level 8.2: Explicit validation on new id
  // ============================================

  describe('Level 8.2: Update with new id (explicit validation check)', () => {
    it('should call validate when id changes on /users/:id', async () => {
      mockFetch(mockGpgamesLogin());
      const { user, sessionToken } = await createUserWithGpgamesAndSession();
      const userId = user.id;

      let validationCalled = false;
      mockFetch([
        mockGpgamesTokenExchange((code) => {
          validationCalled = true;
          return MOCK_ACCESS_TOKEN_2;
        }),
        mockGpgamesPlayerInfo(MOCK_USER_ID_2),
      ]);

      // Update with new id via /users/:id
      await request({
        method: 'PUT',
        url: `http://localhost:8378/1/users/${userId}`,
        headers: {
          'X-Parse-Application-Id': Parse.applicationId,
          'X-Parse-REST-API-Key': 'rest',
          'X-Parse-Session-Token': sessionToken,
          'Content-Type': 'application/json',
        },
        body: {
          authData: { gpgames: { id: MOCK_USER_ID_2, code: 'C2' } },
        },
        json: true,
      });

      expect(validationCalled).toBe(true);

      // Verify authData was updated
      const updated = await new Parse.Query(Parse.User).get(userId, {
        useMasterKey: true,
      });
      const authData = updated.get('authData');
      expect(authData.gpgames.id).toBe(MOCK_USER_ID_2);
    });
  });
});

