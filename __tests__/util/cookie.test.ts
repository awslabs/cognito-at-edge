import { CookieAttributes, Cookies, SAME_SITE_VALUES, getCookieDomain } from '../../src/util/cookie';

describe('parse tests', () => {
  test('should parse valid cookie string', () => {
    const cookieString = [
      'test.cookie.one=test.value.one',
      'test.cookie.two=test.value.two',
    ].join(';');

    expect(Cookies.parse(cookieString))
      .toStrictEqual([
        { name: 'test.cookie.one', value: 'test.value.one' },
        { name: 'test.cookie.two', value: 'test.value.two' },
      ]);
  });

  test('should parse valid cookie string with URI encoded characters', () => {
    const cookieString = '%F0%9F%91%BB%28%29%3C%3E%40%2C%3B%3A%5C%22%2F%5B%5D%3F%3D%7B%7D%20=%20%22%2C%3B=%5C%F0%9F%91%BB';

    expect(Cookies.parse(cookieString))
      .toStrictEqual([
        { name: '👻()<>@,;:\\"/[]?={} ', value: ' ",;=\\👻' },
      ]);
  });

  test('should try to parse cookie even with not-encoded illegal characters', () => {
    const cookieString = '(🤪)<>@,:\\"/[%1Y]?{}%=,\\%"; :=,\\%\\';

    expect(Cookies.parse(cookieString))
      .toStrictEqual([
        { name: '(🤪)<>@,:\\"/[%1Y]?{}%', value: ',\\%"' },
        { name: ':', value: ',\\%\\' },
      ]);
  });

  test('should skip cookies without separator', () => {
    const cookieString = [
      '1.name=value',
      'somestring',
      '2.name=value',
    ].join(';');

    expect(Cookies.parse(cookieString))
      .toStrictEqual([
        { name: '1.name', value: 'value' },
        { name: '2.name', value: 'value' },
      ]);
  });

  test('should return empty array when input parameter is null', () => {
    expect(Cookies.parse(null)).toStrictEqual([]);
  });
});

describe('serialize tests', () => {
  test('should correctly serialize cookie without attributes', () => {
    expect(Cookies.serialize('name', 'value'))
      .toStrictEqual('name=value');
  });

  test('should correctly serialize cookie with defined attributes', () => {
    const attributes: CookieAttributes = {
      domain: 'example.com',
      path: '/path/path',
      expires: new Date(0),
      maxAge: 1,
      secure: true,
      httpOnly: true,
    };

    expect(Cookies.serialize('name', 'value', attributes))
      .toStrictEqual('name=value; Domain=example.com; Path=/path/path; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=1; Secure; HttpOnly');
  });

  test('should skip undefined attributes on serialization', () => {
    const attributes: CookieAttributes = {
      domain: undefined,
      maxAge: 1,
      secure: true,
      httpOnly: true,
    };

    expect(Cookies.serialize('name', 'value', attributes))
      .toStrictEqual('name=value; Max-Age=1; Secure; HttpOnly');
  });

  test('should encode characters not compliant with RFC 6265 and correctly decode it on parse', () => {
    const name = '\t(%)<>@,;🤪:\\"/[]?={ключ} ';
    const value = ' ,<;>\t😉%=\\значение';

    const serialized = Cookies.serialize(name, value);

    expect(serialized)
      .toStrictEqual('%09%28%25%29%3C%3E%40%2C%3B%F0%9F%A4%AA%3A%5C%22%2F%5B%5D%3F%3D%7B%D0%BA%D0%BB%D1%8E%D1%87%7D%20=%20%2C<%3B>%09%F0%9F%98%89%25=%5C%D0%B7%D0%BD%D0%B0%D1%87%D0%B5%D0%BD%D0%B8%D0%B5');

    expect(Cookies.parse(serialized))
      .toStrictEqual([{ name, value }]);
  });

  test('should have correct SAME_SITE_VALUES', () => {
    expect(SAME_SITE_VALUES).toHaveLength(3);
    expect(SAME_SITE_VALUES).toEqual(['Strict', 'Lax', 'None']);
  });
});

describe('getCookieDomain', () => {
  it('should return cloudfront domain when disableCookieDomain is not set and cookieDomain is not set', () => {
    expect(getCookieDomain('example.aws.com', false)).toEqual('example.aws.com');
  });

  it('should return custom domain when cookieDomain is set', () => {
    expect(getCookieDomain('example.aws.com', false, 'aws.com')).toEqual('aws.com');
  });

  it('should return undefined when disableCookieDomain is set', () => {
    expect(getCookieDomain('example.aws.com', true)).toBeUndefined();
  });
});
