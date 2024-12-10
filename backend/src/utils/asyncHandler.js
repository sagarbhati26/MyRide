
const asyncHandler = (fn) => async (req, res, next) => {
    try {
        await fn(req, res, next);
    } catch (error) {
        const statusCode = error.code || 500;
        const message = error.message || 'Internal Server Error';
        res.status(statusCode).json({
            success: false,
            message,
            statusCode
        });
    }
};

export {asyncHandler}