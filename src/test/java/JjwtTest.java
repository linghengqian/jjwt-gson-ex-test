import io.jsonwebtoken.CompressionCodecs;
import io.jsonwebtoken.JwtParserBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

public class JjwtTest {
    @Test
    void testCreatingAJWS() {
        Date firstDate = new Date();
        Date secondDate = new Date(System.currentTimeMillis() + 24 * 60 * 60 * 1000L);
        String uuidString = UUID.randomUUID().toString();
        SecretKey firstKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        String firstCompactJws = Jwts.builder()
                .setSubject("Joe")
                .setHeaderParam("kid", "myKeyId")
                .setIssuer("Aaron")
                .setAudience("Abel")
                .setExpiration(secondDate)
                .setNotBefore(firstDate)
                .setIssuedAt(firstDate)
                .setId(uuidString)
                .claim("exampleClaim", "Adam")
                .signWith(firstKey, SignatureAlgorithm.HS256)
                .compressWith(CompressionCodecs.GZIP)
                .compact();
        JwtParserBuilder jwtParserBuilder = Jwts.parserBuilder().setAllowedClockSkewSeconds(3 * 60).setSigningKey(firstKey);
        assertThat(jwtParserBuilder.build().parseClaimsJws(firstCompactJws).getBody().getSubject()).isEqualTo("Joe");
        assertDoesNotThrow(() -> {
            jwtParserBuilder.requireSubject("Joe").build().parseClaimsJws(firstCompactJws);
            jwtParserBuilder.requireIssuer("Aaron").build().parseClaimsJws(firstCompactJws);
            jwtParserBuilder.requireAudience("Abel").build().parseClaimsJws(firstCompactJws);
        });
        assertDoesNotThrow(()->{
            jwtParserBuilder.requireExpiration(secondDate).build().parseClaimsJws(firstCompactJws);
            jwtParserBuilder.requireNotBefore(firstDate).build().parseClaimsJws(firstCompactJws);
            jwtParserBuilder.requireIssuedAt(firstDate).build().parseClaimsJws(firstCompactJws);
            jwtParserBuilder.requireId(uuidString).build().parseClaimsJws(firstCompactJws);
            jwtParserBuilder.require("exampleClaim", "Adam").build().parseClaimsJws(firstCompactJws);
        });
    }
}
