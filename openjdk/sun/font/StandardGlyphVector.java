/*
  Copyright (C) 2009 - 2013 Volker Berlin (i-net software)

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.

  Jeroen Frijters
  jeroen@frijters.net
  
 */
package sun.font;

import ikvm.awt.IkvmToolkit;

import java.awt.Font;
import java.awt.Shape;
import java.awt.font.FontRenderContext;
import java.awt.font.GlyphMetrics;
import java.awt.font.GlyphJustificationInfo;
import java.awt.font.GlyphVector;
import java.awt.font.LineMetrics;
import java.awt.geom.AffineTransform;
import java.awt.geom.Point2D;
import java.awt.geom.Rectangle2D;
import java.text.CharacterIterator;

import ikvm.internal.NotYetImplementedError;

/**
 * Standard implementation of GlyphVector used by Font, GlyphList, and SunGraphics2D.
 * 
 */
public class StandardGlyphVector extends GlyphVector{
    private Font font;
    private FontRenderContext frc;
    private final String glyphs; // always
    private float[] positions; // only if not default advances



    private Font2D font2D;
    private FontStrike strike;
    
    
    /////////////////////////////
    // Constructors and Factory methods
    /////////////////////////////

    public StandardGlyphVector(Font font, String str, FontRenderContext frc) {
        if(str == null){
            throw new NullPointerException("Glyphs are null");
        }
        this.font = font;
        if( frc == null ){
            frc = new FontRenderContext( null, false, false );
        }
        this.frc = frc;
        this.glyphs = str;
        this.font2D = FontUtilities.getFont2D(font);
        this.strike = font2D.getStrike(font, frc);
    }

    public StandardGlyphVector(Font font, char[] text, FontRenderContext frc) {
        this(font, text, 0, text.length, frc);
    }

    public StandardGlyphVector(Font font, char[] text, int start, int count,
                               FontRenderContext frc) {
        this(font, new String(text, start, count), frc);
    }

    private float getTracking(Font font) {
        if (font.hasLayoutAttributes()) {
            AttributeValues values = ((AttributeMap)font.getAttributes()).getValues();
            return values.getTracking();
        }
        return 0;
    }

    public StandardGlyphVector(Font font, CharacterIterator iter, FontRenderContext frc) {
        this(font, getString(iter), frc);
    }

    public StandardGlyphVector( Font font, int[] glyphs, FontRenderContext frc ) {
        this( font, glyphs2chars(glyphs), frc );
    }
    
    /**
     * Symmetric to {@link #getGlyphCodes(int, int, int[])}
     * Currently there is no real mapping possible between the chars and the glyph IDs in the TTF file
     */
    private static char[] glyphs2chars( int[] glyphs ) {
        int count = glyphs.length;
        char[] text = new char[count];
        for( int i = 0; i < count; ++i ) {
            text[i] = (char)glyphs[i];
        }
        return text;
    }

    /////////////////////////////
    // GlyphVector API
    /////////////////////////////

    @Override
    public Font getFont() {
        return this.font;
    }

    @Override
    public FontRenderContext getFontRenderContext() {
        return this.frc;
    }

    @Override
    public void performDefaultLayout() {
        positions = null;
    }

    @Override
    public int getNumGlyphs() {
        return glyphs.length();
    }

    @Override
    public int getGlyphCode(int glyphIndex) {
        return glyphs.charAt(glyphIndex);
    }

    @Override
    public int[] getGlyphCodes(int start, int count, int[] result) {
        if (count < 0) {
            throw new IllegalArgumentException("count = " + count);
        }
        if (start < 0) {
            throw new IndexOutOfBoundsException("start = " + start);
        }        
        if (start > glyphs.length() - count) { // watch out for overflow if index + count overlarge
            throw new IndexOutOfBoundsException("start + count = " + (start + count));
        }

        if (result == null) {
            result = new int[count];
        }
        for (int i = 0; i < count; ++i) {
            result[i] = glyphs.charAt(i + start);
        }
        return result;
    }

    // !!! not cached, assume TextLayout will cache if necessary
    // !!! reexamine for per-glyph-transforms
    // !!! revisit for text-on-a-path, vertical
    @Override
    public Rectangle2D getLogicalBounds() {
        initPositions();

        LineMetrics lm = font.getLineMetrics("", frc);

        float minX, minY, maxX, maxY;
        // horiz only for now...
        minX = 0;
        minY = -lm.getAscent();
        maxX = 0;
        maxY = lm.getDescent() + lm.getLeading();
        if (glyphs.length() > 0) {
            maxX = positions[positions.length - 2];
        }

        return new Rectangle2D.Float(minX, minY, maxX - minX, maxY - minY);
    }

    // !!! not cached, assume TextLayout will cache if necessary
    @Override
    public Rectangle2D getVisualBounds() {
        return getOutline().getBounds2D();
    }

    @Override
    public Shape getOutline() {
        return getOutline( 0, 0 );
    }

    @Override
    public Shape getOutline(float x, float y) {
        return IkvmToolkit.DefaultToolkit.get().outline( font, frc, glyphs, x, y );
    }

    @Override
    public Shape getGlyphOutline( int glyphIndex ) {
        return getGlyphOutline( glyphIndex, 0, 0 );
    }

    @Override
    public Shape getGlyphOutline( int glyphIndex, float x, float y ) {
        initPositions();
        
        return IkvmToolkit.DefaultToolkit.get().outline( font, frc, glyphs.substring( glyphIndex, glyphIndex + 1 ), x + positions[glyphIndex * 2], y );
    }
    
    @Override
    public Point2D getGlyphPosition(int ix) {
        initPositions();

        ix *= 2;
        return new Point2D.Float(positions[ix], positions[ix + 1]);
    }

    @Override
    public void setGlyphPosition(int ix, Point2D pos) {
        initPositions();

        int ix2 = ix << 1;
        positions[ix2] = (float)pos.getX();
        positions[ix2 + 1] = (float)pos.getY();
    }

    @Override
    public AffineTransform getGlyphTransform(int ix) {
        if (ix < 0 || ix >= glyphs.length) {
            throw new IndexOutOfBoundsException("ix = " + ix);
        }

        if (gti == null) {
            if (newTX == null || newTX.isIdentity()) {
                return;
            }
            gti = new GlyphTransformInfo(this);
        }
        gti.setGlyphTransform(ix, newTX); // sets flags
        if (gti.transformCount() == 0) {
            gti = null;
        }
    }

    @Override
    public float[] getGlyphPositions(int start, int count, float[] result) {
        if (count < 0) {
            throw new IllegalArgumentException("count = " + count);
        }
        if (start < 0) {
            throw new IndexOutOfBoundsException("start = " + start);
        }
        if (start > this.glyphs.length() + 1 - count) {
            throw new IndexOutOfBoundsException("start + count = " + (start + count));
        }
        int count2 = count * 2;
        if( result == null ) {
            result = new float[count2];
        }
        initPositions();
        System.arraycopy( positions, start * 2, result, 0, count2 );
        return result;
    }

    @Override
    public Shape getGlyphLogicalBounds(int ix) {
        if (ix < 0 || ix >= glyphs.length()) {
            throw new IndexOutOfBoundsException("ix = " + ix);
        }

        initPositions();
        StrikeMetrics metrics = strike.getFontMetrics();
        float x = positions[ix * 2];
        return new Rectangle2D.Float( x, -metrics.getAscent(), positions[(ix + 1) * 2] - x, metrics.getAscent()
                        + metrics.getDescent() + metrics.getLeading() );
    }
    
    @Override
    public Shape getGlyphVisualBounds(int ix) {
        if (ix < 0 || ix >= glyphs.length()) {
            throw new IndexOutOfBoundsException("ix = " + ix);
        }

        initPositions();
        return IkvmToolkit.DefaultToolkit.get().outline( font, frc, glyphs.substring( ix, ix + 1 ), positions[ix * 2], 0 );
    }

    @Override
    public GlyphMetrics getGlyphMetrics(int ix) {
        if (ix < 0 || ix >= glyphs.length()) {
            throw new IndexOutOfBoundsException("ix = " + ix);
        }

        Rectangle2D vb = getGlyphVisualBounds(ix).getBounds2D();
        Point2D pt = getGlyphPosition(ix);
        vb.setRect(vb.getMinX() - pt.getX(),
                   vb.getMinY() - pt.getY(),
                   vb.getWidth(),
                   vb.getHeight());
        Point2D.Float adv =
        		strike.getGlyphMetrics( glyphs.charAt( ix ) );
        GlyphMetrics gm = new GlyphMetrics(true, adv.x, adv.y,
                                           vb,
                                          (byte)0);
        return gm;
    }

    @Override
    public GlyphJustificationInfo getGlyphJustificationInfo(int ix) {
        if (ix < 0 || ix >= glyphs.length()) {
            throw new IndexOutOfBoundsException("ix = " + ix);
        }

        // currently we don't have enough information to do this right.  should
        // get info from the font and use real OT/GX justification.  Right now
        // sun/font/ExtendedTextSourceLabel assigns one of three infos
        // based on whether the char is kanji, space, or other.

        return null;
    }

    @Override
    public boolean equals(GlyphVector rhs) {
        if(!(rhs instanceof StandardGlyphVector)){
            return false;
        }
        StandardGlyphVector sgv = (StandardGlyphVector)rhs;
        if(!glyphs.equals(sgv.glyphs)){
            return false;
        }
        if(equals(font, sgv.font)){
            return false;
        }
        if(equals(frc, sgv.frc)){
            return false;
        }
        return true;
    }

    /**
     * Compare 2 objects via equals where both can be null
     */
    private static boolean equals(Object obj1, Object obj2){
        if(obj1 != null){
            if(!obj1.equals(obj2)){
                return false;
            }
        }else{
            if(obj2 != null){
                return false;
            }
        }
        return true;
    }

    /**
     * As a concrete subclass of GlyphVector, this must implement clone.
     */
    @Override
    public Object clone() {
        // positions, gti are mutable so we have to clone them
        // font2d can be shared
        // fsref is a cache and can be shared
        try {
            StandardGlyphVector result = (StandardGlyphVector)super.clone();

            if (positions != null) {
                result.positions = (float[])positions.clone();
            }

            return result;
        }
        catch (CloneNotSupportedException e) {
        }

        return this;
    }

    //////////////////////
    // StandardGlyphVector new public methods
    /////////////////////

    /**
     * Set all the glyph positions, including the 'after last glyph' position.
     * The srcPositions array must be of length (numGlyphs + 1) * 2.
     */
    public void setGlyphPositions(float[] srcPositions) {
        int requiredLength = glyphs.length() * 2 + 2;
        if (srcPositions.length != requiredLength) {
            throw new IllegalArgumentException("srcPositions.length != " + requiredLength);
        }

        positions = (float[])srcPositions.clone();

    }

    /**
     * This is a convenience overload that gets all the glyph positions, which
     * is what you usually want to do if you're getting more than one.
     * !!! should I bother taking result parameter?
     */
    public float[] getGlyphPositions(float[] result) {
        initPositions();
        return positions;
    }

    /**
     * For each glyph return posx, posy, advx, advy, visx, visy, visw, vish.
     */
    public float[] getGlyphInfo() {
        initPositions();
        float[] result = new float[glyphs.length() * 8];
        for (int i = 0, n = 0; i < glyphs.length(); ++i, n += 8) {
            float x = positions[i*2];
            float y = positions[i*2+1];
            result[n] = x;
            result[n+1] = y;

            int glyphID = glyphs.charAt(i);
            Point2D.Float adv = strike.getGlyphMetrics(glyphID);
            result[n+2] = adv.x;
            result[n+3] = adv.y;

            Rectangle2D vb = getGlyphVisualBounds(i).getBounds2D();
            result[n+4] = (float)(vb.getMinX());
            result[n+5] = (float)(vb.getMinY());
            result[n+6] = (float)(vb.getWidth());
            result[n+7] = (float)(vb.getHeight());
        }
        return result;
    }

    @Override
    public void setGlyphTransform(int glyphIndex, AffineTransform newTX){
        throw new NotYetImplementedError();
    }


    /**
     * Convert a CharacterIterator to a string
     * @param iterator the iterator
     * @return the string
     */
    private static String getString(java.text.CharacterIterator iterator){
        iterator.first();
        StringBuilder sb = new StringBuilder();

        while(true){
            char c = iterator.current();
            if(c == CharacterIterator.DONE){
                break;
            }
            sb.append(c);
            iterator.next();
        }

        return sb.toString();
    }

    /**
     * Ensure that the positions array exists and holds position data.
     * If the array is null, this allocates it and sets default positions.
     */
    private void initPositions() {
        if (positions == null) {
            positions = new float[glyphs.length() * 2 + 2];

            Point2D.Float trackPt = null;
            float track = getTracking(font);
            if (track != 0) {
                track *= font.getSize2D();
                trackPt = new Point2D.Float(track, 0); // advance delta
            }

            Point2D.Float pt = new Point2D.Float(0, 0);
            if (font.isTransformed()) {
                AffineTransform at = font.getTransform();
                at.transform(pt, pt);
                positions[0] = pt.x;
                positions[1] = pt.y;

                if (trackPt != null) {
                    at.deltaTransform(trackPt, trackPt);
                }
            }
            for (int i = 0, n = 2; i < glyphs.length(); ++i, n += 2) {
                addDefaultGlyphAdvance(glyphs.charAt(i), pt);
                if (trackPt != null) {
                    pt.x += trackPt.x;
                    pt.y += trackPt.y;
                }
                positions[n] = pt.x;
                positions[n+1] = pt.y;
            }
        }
    }

    private void addDefaultGlyphAdvance(int glyphID, Point2D.Float result) {
        Point2D.Float adv = strike.getGlyphMetrics(glyphID);
        result.x += adv.x;
        result.y += adv.y;
    }
    
    /**
     * If the text is a simple text and we can use FontDesignMetrics without a stackoverflow.
     * @see FontDesignMetrics#stringWidth(String)
     * @return true, if a simple text. false it is a complex text.
     */
	public static boolean isSimpleString(Font font, String str) {
		if (font.hasLayoutAttributes()) {
			return false;
		}
		for (int i = 0; i < str.length(); ++i) {
			if (FontUtilities.isNonSimpleChar(str.charAt(i))) {
				return false;
			}
		}
		return true;
	}
	    /////////////////////
    // Internal utility classes
    /////////////////////

    // !!! I have this as a separate class instead of just inside SGV,
    // but I previously didn't bother.  Now I'm trying this again.
    // Probably still not worth it, but I'd like to keep sgv's small in the common case.

    static final class GlyphTransformInfo {
        StandardGlyphVector sgv;  // reference back to glyph vector - yuck
        int[] indices;            // index into unique strikes
        double[] transforms;      // six doubles per unique transform, because AT is a pain to manipulate
        SoftReference strikesRef; // ref to unique strikes, one per transform
        boolean haveAllStrikes;   // true if the strike array has been filled by getStrikes().

        // used when first setting a transform
        GlyphTransformInfo(StandardGlyphVector sgv) {
            this.sgv = sgv;
        }

        // used when cloning a glyph vector, need to set back link
        GlyphTransformInfo(StandardGlyphVector sgv, GlyphTransformInfo rhs) {
            this.sgv = sgv;

            this.indices = rhs.indices == null ? null : (int[])rhs.indices.clone();
            this.transforms = rhs.transforms == null ? null : (double[])rhs.transforms.clone();
            this.strikesRef = null; // can't share cache, so rather than clone, we just null out
        }

        // used in sgv equality
        public boolean equals(GlyphTransformInfo rhs) {
            if (rhs == null) {
                return false;
            }
            if (rhs == this) {
                return true;
            }
            if (this.indices.length != rhs.indices.length) {
                return false;
            }
            if (this.transforms.length != rhs.transforms.length) {
                return false;
            }

            // slow since we end up processing the same transforms multiple
            // times, but since transforms can be in any order, we either do
            // this or create a mapping.  Equality tests aren't common so
            // leave it like this.
            for (int i = 0; i < this.indices.length; ++i) {
                int tix = this.indices[i];
                int rix = rhs.indices[i];
                if ((tix == 0) != (rix == 0)) {
                    return false;
                }
                if (tix != 0) {
                    tix *= 6;
                    rix *= 6;
                    for (int j = 6; j > 0; --j) {
                        if (this.indices[--tix] != rhs.indices[--rix]) {
                            return false;
                        }
                    }
                }
            }
            return true;
        }

        // implements sgv.setGlyphTransform
        void setGlyphTransform(int glyphIndex, AffineTransform newTX) {

            // we store all the glyph transforms as a double array, and for each glyph there
            // is an entry in the txIndices array indicating which transform to use.  0 means
            // there's no transform, 1 means use the first transform (the 6 doubles at offset
            // 0), 2 means use the second transform (the 6 doubles at offset 6), etc.
            //
            // Since this can be called multiple times, and since the number of transforms
            // affects the time it takes to construct the glyphs, we try to keep the arrays as
            // compact as possible, by removing transforms that are no longer used, and reusing
            // transforms where we already have them.

            double[] temp = new double[6];
            boolean isIdentity = true;
            if (newTX == null || newTX.isIdentity()) {
                // Fill in temp
                temp[0] = temp[3] = 1.0;
            }
            else {
                isIdentity = false;
                newTX.getMatrix(temp);
            }

            if (indices == null) {
                if (isIdentity) { // no change
                    return;
                }

                indices = new int[sgv.glyphs.length];
                indices[glyphIndex] = 1;
                transforms = temp;
            } else {
                boolean addSlot = false; // assume we're not growing
                int newIndex = -1;
                if (isIdentity) {
                    newIndex = 0; // might shrink
                } else {
                    addSlot = true; // assume no match
                    int i;
                loop:
                    for (i = 0; i < transforms.length; i += 6) {
                        for (int j = 0; j < 6; ++j) {
                            if (transforms[i + j] != temp[j]) {
                                continue loop;
                            }
                        }
                        addSlot = false;
                        break;
                    }
                    newIndex = i / 6 + 1; // if no match, end of list
                }

                // if we're using the same transform, nothing to do
                int oldIndex = indices[glyphIndex];
                if (newIndex != oldIndex) {
                    // see if we are removing last use of the old slot
                    boolean removeSlot = false;
                    if (oldIndex != 0) {
                        removeSlot = true;
                        for (int i = 0; i < indices.length; ++i) {
                            if (indices[i] == oldIndex && i != glyphIndex) {
                                removeSlot = false;
                                break;
                            }
                        }
                    }

                    if (removeSlot && addSlot) { // reuse old slot with new transform
                        newIndex = oldIndex;
                        System.arraycopy(temp, 0, transforms, (newIndex - 1) * 6, 6);
                    } else if (removeSlot) {
                        if (transforms.length == 6) { // removing last one, so clear arrays
                            indices = null;
                            transforms = null;

                            sgv.clearCaches(glyphIndex);
                            sgv.clearFlags(FLAG_HAS_TRANSFORMS);
                            strikesRef = null;

                            return;
                        }

                        double[] ttemp = new double[transforms.length - 6];
                        System.arraycopy(transforms, 0, ttemp, 0, (oldIndex - 1) * 6);
                        System.arraycopy(transforms, oldIndex * 6, ttemp, (oldIndex - 1) * 6,
                                         transforms.length - oldIndex * 6);
                        transforms = ttemp;

                        // clean up indices
                        for (int i = 0; i < indices.length; ++i) {
                            if (indices[i] > oldIndex) { // ignore == oldIndex, it's going away
                                indices[i] -= 1;
                            }
                        }
                        if (newIndex > oldIndex) { // don't forget to decrement this too if we need to
                            --newIndex;
                        }
                    } else if (addSlot) {
                        double[] ttemp = new double[transforms.length + 6];
                        System.arraycopy(transforms, 0, ttemp, 0, transforms.length);
                        System.arraycopy(temp, 0, ttemp, transforms.length, 6);
                        transforms = ttemp;
                    }

                    indices[glyphIndex] = newIndex;
                }
            }

            sgv.clearCaches(glyphIndex);
            sgv.addFlags(FLAG_HAS_TRANSFORMS);
            strikesRef = null;
        }

        // implements sgv.getGlyphTransform
        AffineTransform getGlyphTransform(int ix) {
            int index = indices[ix];
            if (index == 0) {
                return null;
            }

            int x = (index - 1) * 6;
            return new AffineTransform(transforms[x + 0],
                                       transforms[x + 1],
                                       transforms[x + 2],
                                       transforms[x + 3],
                                       transforms[x + 4],
                                       transforms[x + 5]);
        }

        int transformCount() {
            if (transforms == null) {
                return 0;
            }
            return transforms.length / 6;
        }

        /**
         * The strike cache works like this.
         *
         * -Each glyph is thought of as having a transform, usually identity.
         * -Each request for a strike is based on a device transform, either the
         * one in the frc or the rendering transform.
         * -For general info, strikes are held with soft references.
         * -When rendering, strikes must be held with hard references for the
         * duration of the rendering call.  GlyphList will have to hold this
         * info along with the image and position info, but toss the strike info
         * when done.
         * -Build the strike cache as needed.  If the dev transform we want to use
         * has changed from the last time it is built, the cache is flushed by
         * the caller before these methods are called.
         *
         * Use a tx that doesn't include translation components of dst tx.
         */
        Object setupGlyphImages(long[] images, float[] positions, AffineTransform tx) {
            int len = sgv.glyphs.length;

            GlyphStrike[] sl = getAllStrikes();
            for (int i = 0; i < len; ++i) {
                GlyphStrike gs = sl[indices[i]];
                int glyphID = sgv.glyphs[i];
                images[i] = gs.strike.getGlyphImagePtr(glyphID);

                gs.getGlyphPosition(glyphID, i*2, sgv.positions, positions);
            }
            tx.transform(positions, 0, positions, 0, len);

            return sl;
        }

        Rectangle getGlyphsPixelBounds(AffineTransform tx, float x, float y, int start, int count) {
            Rectangle result = null;
            Rectangle r = new Rectangle();
            Point2D.Float pt = new Point.Float();
            int n = start * 2;
            while (--count >= 0) {
                GlyphStrike gs = getStrike(start);
                pt.x = x + sgv.positions[n++] + gs.dx;
                pt.y = y + sgv.positions[n++] + gs.dy;
                tx.transform(pt, pt);
                gs.strike.getGlyphImageBounds(sgv.glyphs[start++], pt, r);
                if (!r.isEmpty()) {
                    if (result == null) {
                        result = new Rectangle(r);
                    } else {
                        result.add(r);
                    }
                }
            }
            return result != null ? result : r;
        }

        GlyphStrike getStrike(int glyphIndex) {
            if (indices != null) {
                GlyphStrike[] strikes = getStrikeArray();
                return getStrikeAtIndex(strikes, indices[glyphIndex]);
            }
            return sgv.getDefaultStrike();
        }

        private GlyphStrike[] getAllStrikes() {
            if (indices == null) {
                return null;
            }

            GlyphStrike[] strikes = getStrikeArray();
            if (!haveAllStrikes) {
                for (int i = 0; i < strikes.length; ++i) {
                    getStrikeAtIndex(strikes, i);
                }
                haveAllStrikes = true;
            }

            return strikes;
        }

        private GlyphStrike[] getStrikeArray() {
            GlyphStrike[] strikes = null;
            if (strikesRef != null) {
                strikes = (GlyphStrike[])strikesRef.get();
            }
            if (strikes == null) {
                haveAllStrikes = false;
                strikes = new GlyphStrike[transformCount() + 1];
                strikesRef = new SoftReference(strikes);
            }

            return strikes;
        }

        private GlyphStrike getStrikeAtIndex(GlyphStrike[] strikes, int strikeIndex) {
            GlyphStrike strike = strikes[strikeIndex];
            if (strike == null) {
                if (strikeIndex == 0) {
                    strike = sgv.getDefaultStrike();
                } else {
                    int ix = (strikeIndex - 1) * 6;
                    AffineTransform gtx = new AffineTransform(transforms[ix],
                                                              transforms[ix+1],
                                                              transforms[ix+2],
                                                              transforms[ix+3],
                                                              transforms[ix+4],
                                                              transforms[ix+5]);

                    strike = GlyphStrike.create(sgv, sgv.dtx, gtx);
                }
                strikes[strikeIndex] = strike;
            }
            return strike;
        }
    }

    // This adjusts the metrics by the translation components of the glyph
    // transform.  It is done here since the translation is not known by the
    // strike.
    // It adjusts the position of the image and the advance.

    public static final class GlyphStrike {
        StandardGlyphVector sgv;
        FontStrike strike; // hard reference
        float dx;
        float dy;

        static GlyphStrike create(StandardGlyphVector sgv, AffineTransform dtx, AffineTransform gtx) {
            float dx = 0;
            float dy = 0;

            AffineTransform tx = sgv.ftx;
            if (!dtx.isIdentity() || gtx != null) {
                tx = new AffineTransform(sgv.ftx);
                if (gtx != null) {
                    tx.preConcatenate(gtx);
                    dx = (float)tx.getTranslateX(); // uses ftx then gtx to get translation
                    dy = (float)tx.getTranslateY();
                }
                if (!dtx.isIdentity()) {
                    tx.preConcatenate(dtx);
                }
            }

            int ptSize = 1; // only matters for 'gasp' case.
            Object aaHint = sgv.frc.getAntiAliasingHint();
            if (aaHint == VALUE_TEXT_ANTIALIAS_GASP) {
                /* Must pass in the calculated point size for rendering.
                 * If the glyph tx is anything other than identity or a
                 *  simple translate, calculate the transformed point size.
                 */
                if (!tx.isIdentity() &&
                    (tx.getType() & ~AffineTransform.TYPE_TRANSLATION) != 0) {
                    double shearx = tx.getShearX();
                    if (shearx != 0) {
                        double scaley = tx.getScaleY();
                        ptSize =
                            (int)Math.sqrt(shearx * shearx + scaley * scaley);
                    } else {
                        ptSize = (int)(Math.abs(tx.getScaleY()));
                    }
                }
            }
            int aa = FontStrikeDesc.getAAHintIntVal(aaHint,sgv.font2D, ptSize);
            int fm = FontStrikeDesc.getFMHintIntVal
                (sgv.frc.getFractionalMetricsHint());
            FontStrikeDesc desc = new FontStrikeDesc(dtx,
                                                     tx,
                                                     sgv.font.getStyle(),
                                                     aa, fm);
            // Get the strike via the handle. Shouldn't matter
            // if we've invalidated the font but its an extra precaution.
        // do we want the CompFont from CFont here ?
        Font2D f2d = sgv.font2D;
        if (f2d instanceof FontSubstitution) {
           f2d = ((FontSubstitution)f2d).getCompositeFont2D();
        }
            FontStrike strike = f2d.handle.font2D.getStrike(desc);  // !!! getStrike(desc, false)

            return new GlyphStrike(sgv, strike, dx, dy);
        }

        private GlyphStrike(StandardGlyphVector sgv, FontStrike strike, float dx, float dy) {
            this.sgv = sgv;
            this.strike = strike;
            this.dx = dx;
            this.dy = dy;
        }

        void getADL(ADL result) {
            StrikeMetrics sm = strike.getFontMetrics();
            Point2D.Float delta = null;
            if (sgv.font.isTransformed()) {
                delta = new Point2D.Float();
                delta.x = (float)sgv.font.getTransform().getTranslateX();
                delta.y = (float)sgv.font.getTransform().getTranslateY();
            }

            result.ascentX = -sm.ascentX;
            result.ascentY = -sm.ascentY;
            result.descentX = sm.descentX;
            result.descentY = sm.descentY;
            result.leadingX = sm.leadingX;
            result.leadingY = sm.leadingY;
        }

        void getGlyphPosition(int glyphID, int ix, float[] positions, float[] result) {
            result[ix] = positions[ix] + dx;
            ++ix;
            result[ix] = positions[ix] + dy;
        }

        void addDefaultGlyphAdvance(int glyphID, Point2D.Float result) {
            // !!! change this API?  Creates unnecessary garbage.  Also the name doesn't quite fit.
            // strike.addGlyphAdvance(Point2D.Float adv);  // hey, whaddya know, matches my api :-)
            Point2D.Float adv = strike.getGlyphMetrics(glyphID);
            result.x += adv.x + dx;
            result.y += adv.y + dy;
        }

        Rectangle2D getGlyphOutlineBounds(int glyphID, float x, float y) {
            Rectangle2D result = null;
            if (sgv.invdtx == null) {
                result = new Rectangle2D.Float();
                result.setRect(strike.getGlyphOutlineBounds(glyphID)); // don't mutate cached rect
            } else {
                GeneralPath gp = strike.getGlyphOutline(glyphID, 0, 0);
                gp.transform(sgv.invdtx);
                result = gp.getBounds2D();
            }
            /* Since x is the logical advance of the glyph to this point.
             * Because of the way that Rectangle.union is specified, this
             * means that subsequent unioning of a rect including that
             * will be affected, even if the glyph is empty. So skip such
             * cases. This alone isn't a complete solution since x==0
             * may also not be what is wanted. The code that does the
             * unioning also needs to be aware to ignore empty glyphs.
             */
            if (!result.isEmpty()) {
                result.setRect(result.getMinX() + x + dx,
                               result.getMinY() + y + dy,
                               result.getWidth(), result.getHeight());
            }
            return result;
        }

        void appendGlyphOutline(int glyphID, GeneralPath result, float x, float y) {
            // !!! fontStrike needs a method for this.  For that matter, GeneralPath does.
            GeneralPath gp = null;
            if (sgv.invdtx == null) {
                gp = strike.getGlyphOutline(glyphID, x + dx, y + dy);
            } else {
                gp = strike.getGlyphOutline(glyphID, 0, 0);
                gp.transform(sgv.invdtx);
                gp.transform(AffineTransform.getTranslateInstance(x + dx, y + dy));
            }
            PathIterator iterator = gp.getPathIterator(null);
            result.append(iterator, false);
        }
    }

    public String toString() {
        return appendString(null).toString();
    }

    StringBuffer appendString(StringBuffer buf) {
        if (buf == null) {
            buf = new StringBuffer();
        }
        try {
            buf.append("SGV{font: ");
            buf.append(font.toString());
            buf.append(", frc: ");
            buf.append(frc.toString());
            buf.append(", glyphs: (");
            buf.append(glyphs.length);
            buf.append(")[");
            for (int i = 0; i < glyphs.length; ++i) {
                if (i > 0) {
                    buf.append(", ");
                }
                buf.append(Integer.toHexString(glyphs[i]));
            }
            buf.append("]");
            if (positions != null) {
                buf.append(", positions: (");
                buf.append(positions.length);
                buf.append(")[");
                for (int i = 0; i < positions.length; i += 2) {
                    if (i > 0) {
                        buf.append(", ");
                    }
                    buf.append(positions[i]);
                    buf.append("@");
                    buf.append(positions[i+1]);
                }
                buf.append("]");
            }
            if (charIndices != null) {
                buf.append(", indices: (");
                buf.append(charIndices.length);
                buf.append(")[");
                for (int i = 0; i < charIndices.length; ++i) {
                    if (i > 0) {
                        buf.append(", ");
                    }
                    buf.append(charIndices[i]);
                }
                buf.append("]");
            }
            buf.append(", flags:");
            if (getLayoutFlags() == 0) {
                buf.append(" default");
            } else {
                if ((flags & FLAG_HAS_TRANSFORMS) != 0) {
                    buf.append(" tx");
                }
                if ((flags & FLAG_HAS_POSITION_ADJUSTMENTS) != 0) {
                    buf.append(" pos");
                }
                if ((flags & FLAG_RUN_RTL) != 0) {
                    buf.append(" rtl");
                }
                if ((flags & FLAG_COMPLEX_GLYPHS) != 0) {
                    buf.append(" complex");
                }
            }
        }
        catch(Exception e) {
            buf.append(" " + e.getMessage());
        }
        buf.append("}");

        return buf;
    }

    static class ADL {
        public float ascentX;
        public float ascentY;
        public float descentX;
        public float descentY;
        public float leadingX;
        public float leadingY;

        public String toString() {
            return toStringBuffer(null).toString();
        }

        protected StringBuffer toStringBuffer(StringBuffer result) {
            if (result == null) {
                result = new StringBuffer();
            }
            result.append("ax: ");
            result.append(ascentX);
            result.append(" ay: ");
            result.append(ascentY);
            result.append(" dx: ");
            result.append(descentX);
            result.append(" dy: ");
            result.append(descentY);
            result.append(" lx: ");
            result.append(leadingX);
            result.append(" ly: ");
            result.append(leadingY);

            return result;
        }
    }
}
