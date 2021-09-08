/* 
 * Copyright 2010 Aalto University, ComNet
 * Released under GPLv3. See LICENSE.txt for details. 
 */
package movement;

import core.Coord;
import core.Settings;

/**
 * Random waypoint movement model. Creates zig-zag paths within the simulation
 * area.
 */
public class RandomWaypointBtc extends MovementModel {

    /**
     * how many waypoints should there be per path
     */
    private static final int PATH_LENGTH = 1;
    private Coord lastWaypoint;
    private Double randX, randY;

    public RandomWaypointBtc(Settings settings) {
        super(settings);
    }

    protected RandomWaypointBtc(RandomWaypointBtc rwp) {
        super(rwp);
    }

    /**
     * Returns a possible (random) placement for a host
     *
     * @return Random position on the map
     */
    @Override
    public Coord getInitialLocation() {
        assert rng != null : "MovementModel not initialized!";
        Coord c = randomCoord();

        this.lastWaypoint = c;
        return c;
    }

    @Override
    public Path getPath() {
        Path p;
        p = new Path(generateSpeed());
        p.addWaypoint(lastWaypoint.clone());
        Coord c = lastWaypoint;

        for (int i = 0; i < PATH_LENGTH; i++) {
            c = randomCoord();
            p.addWaypoint(c);
        }

        this.lastWaypoint = c;
        return p;
    }

    @Override
    public RandomWaypointBtc replicate() {
        return new RandomWaypointBtc(this);
    }

    protected Coord randomCoord() {
        switch (this.moveArea) {
            case 1:
                randX = ((getMaxX() / 3) - 0) * rng.nextDouble() + 0;
                randY = ((getMaxY() / 3) - 0) * rng.nextDouble() + 0;
                return new Coord(randX, randY);
            case 2:
                randX = (getMaxX() - (getMaxX()*2/3)) * rng.nextDouble() + (getMaxX()*2/3);
                randY = ((getMaxY()/3) - 0) * rng.nextDouble() + 0;
		return new Coord(randX,	randY);
            case 3:
                randX = ((getMaxX()*2/3) - (getMaxX()/3)) * rng.nextDouble() + (getMaxX()/3);
                randY = ((getMaxY()*2/3) - (getMaxY()/3)) * rng.nextDouble() + (getMaxY()/3);
		return new Coord(randX,	randY);
            case 4:
                randX = ((getMaxX()/3) - 0) * rng.nextDouble() + 0;
                randY = (getMaxY() - (getMaxY()*2/3)) * rng.nextDouble() + (getMaxY()*2/3);
		return new Coord(randX,	randY);
            case 5:
                randX = (getMaxX() - (getMaxX()*2/3)) * rng.nextDouble() + (getMaxX()*2/3);
                randY = (getMaxY() - (getMaxY()*2/3)) * rng.nextDouble() + (getMaxY()*2/3);
		return new Coord(randX,	randY);
            default:
                return new Coord(rng.nextDouble() * getMaxX(),
                        rng.nextDouble() * getMaxY());
        }

    }
}
